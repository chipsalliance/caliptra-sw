// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{firmware::APP_MLDSA_ATTESTATION, ImageOptions};
use caliptra_common::checksum::calc_checksum;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SetPqSeedReq, SET_PQ_SEED_SEED_SIZE,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use zerocopy::IntoBytes;

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

#[test]
fn test_set_pq_seed_pl1_rejected() {
    // SET_PQ_SEED is PL0-only. Boot with no PL0 pauser so the caller is PL1.
    let mut image_opts = ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        test_image_options: Some(image_opts),
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

    let resp = model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
        resp,
    );
}

#[test]
fn test_set_pq_seed_attestation_disabled() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_MLDSA_ATTESTATION),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Disable attestation before provisioning the PQ seed.
    let payload = MailboxReqHeader {
        chksum: calc_checksum(u32::from(CommandId::DISABLE_ATTESTATION), &[]),
    };
    model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .expect("DISABLE_ATTESTATION failed");

    // With attestation disabled, provisioning the PQ.DevID CDI must be rejected.
    let mut cmd = MailboxReq::SetPqSeed(SetPqSeedReq {
        hdr: MailboxReqHeader { chksum: 0 },
        seed: [0x5a; SET_PQ_SEED_SEED_SIZE],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::SET_PQ_SEED), cmd.as_bytes().unwrap())
        .unwrap_err();
    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SET_PQ_SEED_ATTESTATION_DISABLED,
        resp,
    );
}
