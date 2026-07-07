// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::APP_MLDSA_ATTESTATION;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};

#[test]
fn test_set_pq_seed() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap());
    assert!(resp.is_ok());
}

#[test]
fn test_repeated_set_pq_seed_rejected() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap());
    assert!(resp.is_ok());
    let resp = model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SET_PQ_SEED_ALREADY_SET,
        resp,
    );
}
