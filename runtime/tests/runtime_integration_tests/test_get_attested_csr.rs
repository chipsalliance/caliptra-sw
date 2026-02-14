// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_common::mailbox_api::{
    AttestedCsrResp, CommandId, GetAttestedEccCsrReq, MailboxReq, MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;

use crate::common::{assert_error, run_rt_test, RuntimeTestArgs};
use zerocopy::IntoBytes;

#[test]
fn test_get_attested_ldevid_ecc_csr() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut get_attested_csr_cmd = MailboxReq::GetAttestedEcc384Csr(GetAttestedEccCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 1, // LDEVID
        nonce: [0u8; 32],
    });
    get_attested_csr_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_ECC384_CSR),
            get_attested_csr_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    assert!(resp.len() <= std::mem::size_of::<AttestedCsrResp>());
    let mut csr_resp = AttestedCsrResp::default();
    csr_resp.as_mut_bytes()[..resp.len()].copy_from_slice(&resp);

    assert!(csr_resp.data.iter().any(|&x| x != 0));
}

#[test]
fn test_get_attested_csr_invalid_key_id() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut get_attested_csr_cmd = MailboxReq::GetAttestedEcc384Csr(GetAttestedEccCsrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key_id: 0,
        nonce: [0u8; 32],
    });
    get_attested_csr_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_ATTESTED_ECC384_CSR),
            get_attested_csr_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );
}
