// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    CommandId, GetAttestedEccCsrReq, GetAttestedMldsaCsrReq, MailboxReq, MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_attested_csr_invalid_key_id() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::GetAttestedEcc384Csr(GetAttestedEccCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 0, // Invalid: valid key IDs are 1, 2, 3
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_ECC384_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}

#[test]
fn test_get_attested_mldsa_csr_invalid_key_id() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::GetAttestedMldsa87Csr(GetAttestedMldsaCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 0, // Invalid: valid key IDs are 1, 2, 3
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_MLDSA87_CSR),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}
