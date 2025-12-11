// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockDeriveMekReq, OcpLockDeriveMekResp,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};

use crate::test_ocp_lock::InitializeMekSecretParams;

use super::{boot_ocp_lock_runtime, OcpLockBootParams};

use zerocopy::{FromBytes, IntoBytes};

/// Temporary checksum. This will be calculated from the full keyladder.
const EXPECTED_MEK_CHECKSUM: [u8; 16] = [
    73, 146, 30, 45, 219, 194, 205, 122, 216, 126, 125, 129, 216, 54, 127, 49,
];

// TODO(clundin): Follow up with the following test cases:
//
// These follow ups are pending an independently constructed key ladder / splitting into smaller
// PRs.
//
// * Release MEK and validate MEK contents.
// * Validate MEK checksum is correct.
// * MEK and MEK checksum are the same after a warm reset.
// * MEK and MEK checksum are the same after a hitless update to new firmware.

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: EXPECTED_MEK_CHECKSUM,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model
        .mailbox_execute(
            CommandId::OCP_LOCK_DERIVE_MEK.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_eq!(&response.mek_checksum, &EXPECTED_MEK_CHECKSUM);
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_corrupted_sek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xBE; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: EXPECTED_MEK_CHECKSUM,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        response.unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_MEK_CHKSUM_FAIL.into(),)
    );
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_corrupted_sek_no_checksum() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xBE; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model
        .mailbox_execute(
            CommandId::OCP_LOCK_DERIVE_MEK.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_ne!(&response.mek_checksum, &EXPECTED_MEK_CHECKSUM);
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_missing_secret_seed() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: [0; 16],
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        response.unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),)
    );
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_consumed_secret_seed() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: [0; 16],
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    // Consumes the `MEK_SECRET_SEED` so `DERIVE_MEK` will not work until another call to `INITIALIZE_MEK_SECRET`
    let response = model
        .mailbox_execute(
            CommandId::OCP_LOCK_DERIVE_MEK.into(),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_eq!(&response.mek_checksum, &EXPECTED_MEK_CHECKSUM);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        response.unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),)
    );
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_missing_hek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: false,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: [0; 16],
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        response.unwrap_err(),
        ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),)
    );
}
