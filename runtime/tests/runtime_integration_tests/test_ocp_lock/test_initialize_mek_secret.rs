// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockInitializeMekSecretReq,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;

use super::{boot_ocp_lock_runtime, validate_ocp_lock_response, OcpLockBootParams};

#[test]
fn test_valid_mek_secret_seed() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    // Initialize MEK Secret Seed
    let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        sek: [0xAB; 32],
        dpk: [0xCD; 32],
    });
    cmd.populate_chksum().unwrap();
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        response.unwrap().unwrap();
    });
}

#[test]
fn test_initialize_mek_secret_no_hek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams::default());

    let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        sek: [0xAB; 32],
        dpk: [0xCD; 32],
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE.into(),)
        );
    });
}
