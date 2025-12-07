// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockInitializeMekSecretReq,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;

use super::{boot_ocp_lock_runtime, supports_ocp_lock, OcpLockBootParams};

// TODO(clundin): Validate MEK Secret Seed contents by constructing key ladder in other OCP LOCK
// commands.

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
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
    if supports_ocp_lock(&mut model) {
        response.unwrap().unwrap();
    } else {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into(),
            )
        );
    }
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

    if supports_ocp_lock(&mut model) {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE.into(),)
        );
    } else {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND.into(),
            )
        );
    }
}
