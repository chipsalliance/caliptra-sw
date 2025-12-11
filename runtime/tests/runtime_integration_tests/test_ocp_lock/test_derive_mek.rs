// Licensed under the Apache-2.0 license

use std::sync::LazyLock;

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockDeriveMekReq, OcpLockDeriveMekResp,
    OcpLockInitializeMekSecretReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError, SecurityState};
use caliptra_test::derive::{DoeInput, DoeOutput, Mek, OcpLockKeyLadderBuilder};

use crate::test_ocp_lock::InitializeMekSecretParams;

use super::{boot_ocp_lock_runtime, validate_ocp_lock_response, OcpLockBootParams};

use zerocopy::{FromBytes, IntoBytes};

static EXPECTED_MEK: LazyLock<Mek> = LazyLock::new(|| {
    // Match the input params for the OCP LOCK Key ladder
    // * Same UDS / FE
    // * Same HEK
    // * Same DPK / SEK
    //
    // This should create the same MEK that Caliptra does.
    let doe_out = DoeOutput::generate(&DoeInput::default());
    OcpLockKeyLadderBuilder::new(doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32])
        .derive_mek()
});

// TODO(clundin): Follow up with the following test cases:
//
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
        mek_checksum: EXPECTED_MEK.checksum,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_eq!(actual_mek.mek, EXPECTED_MEK.mek);
    });
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
/// Verifies MEK does not change after a warm reset.
fn test_derive_mek_warm_reset() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut derive_mek_cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: EXPECTED_MEK.checksum,
        ..Default::default()
    });
    derive_mek_cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        derive_mek_cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_eq!(actual_mek.mek, EXPECTED_MEK.mek);
    });

    model.warm_reset_flow().unwrap();

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

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        derive_mek_cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_eq!(actual_mek.mek, EXPECTED_MEK.mek);
    });
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_warm_reset_wipes_intermediate_secret() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    model.warm_reset_flow().unwrap();

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: EXPECTED_MEK.checksum,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_debug_unlocked() {
    let debug_unlocked_doe_out = DoeOutput::generate(&DoeInput::debug_unlocked());
    let expected_debug_unlocked_mek = OcpLockKeyLadderBuilder::new(debug_unlocked_doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32])
        .derive_mek();

    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Unprovisioned)
                .set_debug_locked(false),
        ),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: expected_debug_unlocked_mek.checksum,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(response.mek_checksum, expected_debug_unlocked_mek.checksum);
        assert_eq!(actual_mek.mek, expected_debug_unlocked_mek.mek);

        // Debug unlocked should not match the production UDS & FE.
        assert_ne!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_ne!(actual_mek.mek, EXPECTED_MEK.mek);
    });
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
        mek_checksum: EXPECTED_MEK.checksum,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_MEK_CHKSUM_FAIL.into(),)
        );
    });
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

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_ne!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_ne!(actual_mek.mek, EXPECTED_MEK.mek);
    });
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
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
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_eq!(actual_mek.mek, EXPECTED_MEK.mek);
    });

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );
    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into(),
            )
        );
    });
}
