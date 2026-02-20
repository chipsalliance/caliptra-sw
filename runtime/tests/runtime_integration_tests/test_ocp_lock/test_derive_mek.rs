// Licensed under the Apache-2.0 license

use std::sync::LazyLock;

use caliptra_api::mailbox::{
    CommandId, MailboxReq, MailboxReqHeader, OcpLockDeriveMekReq, OcpLockDeriveMekResp,
    OcpLockInitializeMekSecretReq, OcpLockMixMpkReq, WrappedKey,
    OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART_OCP_LOCK_FPGA, FMC_FPGA_WITH_UART},
    ImageOptions,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError, SecurityState};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_test::derive::{DoeInput, DoeOutput, Mek, OcpLockKeyLadderBuilder};

use crate::test_ocp_lock::InitializeMekSecretParams;

use super::{
    boot_ocp_lock_runtime, get_enabled_mpk, get_validated_hpke_handle, validate_ocp_lock_response,
    OcpLockBootParams,
};

use zerocopy::{FromBytes, IntoBytes};

const LOCKED_MPK_TYPE: u16 = 0x1;

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

// TODO(clundin): Make tests work on emulator.
#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_hitless_update() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });
    verify_derive_mek(&mut model, &EXPECTED_MEK);
    update_fw(&mut model);
    initialize_mek_secret(&mut model);
    verify_derive_mek(&mut model, &EXPECTED_MEK);
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_mix_mpk_hitless_update() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let doe_out = DoeOutput::generate(&DoeInput::default());
    let mut builder = OcpLockKeyLadderBuilder::new(doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32]);

    let mpks = mix_mpk_flow(&mut model, &mut builder, None);

    let expected_mek = builder.derive_mek();
    verify_derive_mek(&mut model, &expected_mek);

    update_fw(&mut model);

    initialize_mek_secret(&mut model);

    let mut new_builder = OcpLockKeyLadderBuilder::new(doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32]);

    mix_mpk_flow(&mut model, &mut new_builder, Some(&mpks));

    let new_expected_mek = new_builder.derive_mek();

    // MEK should not change after hitless update
    assert_eq!(expected_mek.checksum, new_expected_mek.checksum);
    assert_eq!(expected_mek.mek, new_expected_mek.mek);

    verify_derive_mek(&mut model, &new_expected_mek);
}

fn verify_derive_mek(model: &mut DefaultHwModel, expected_mek: &Mek) {
    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: expected_mek.checksum,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_DERIVE_MEK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(model, response, |response, actual_mek| {
        let response = response.unwrap().unwrap();
        let response = OcpLockDeriveMekResp::ref_from_bytes(response.as_bytes()).unwrap();
        let actual_mek = actual_mek.unwrap();
        assert_eq!(response.mek_checksum, expected_mek.checksum);
        assert_eq!(actual_mek.mek, expected_mek.mek);
    });
}

fn initialize_mek_secret(model: &mut DefaultHwModel) {
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
    validate_ocp_lock_response(model, response, |response, _| {
        response.unwrap().unwrap();
    });
}

fn mix_mpk_flow(
    model: &mut DefaultHwModel,
    builder: &mut OcpLockKeyLadderBuilder,
    mpks: Option<&[(WrappedKey, WrappedKey)]>,
) -> Vec<(WrappedKey, WrappedKey)> {
    let endorsed_handle = get_validated_hpke_handle(model).unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];

    let aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(LOCKED_MPK_TYPE.as_bytes());
        aad.extend_from_slice((metadata.len() as u32).as_bytes());
        aad.extend_from_slice(metadata.as_bytes());
        aad
    };

    let mut result_mpks = Vec::new();

    if let Some(mpks) = mpks {
        for (enabled_mpk, locked_mpk) in mpks {
            let mpk = builder.decrypt_locked_mpk([0xAB; 32], &access_key, &aad, &locked_mpk.into());
            builder.mix_mpk(&mpk);

            let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
                enabled_mpk: enabled_mpk.clone(),
                ..Default::default()
            });
            cmd.populate_chksum().unwrap();

            let response =
                model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

            validate_ocp_lock_response(model, response, |response, _| {
                let _ = response.unwrap().unwrap();
            });
            result_mpks.push((enabled_mpk.clone(), locked_mpk.clone()));
        }
    } else {
        for _ in 0..3 {
            let mix_mpk_cb = |mpk: &WrappedKey| {
                let mpk = builder.decrypt_locked_mpk([0xAB; 32], &access_key, &aad, &mpk.into());
                builder.mix_mpk(&mpk);
            };

            let (enabled_mpk, locked_mpk) = get_enabled_mpk(
                model,
                &endorsed_handle,
                &info,
                &metadata,
                &access_key,
                Some(mix_mpk_cb),
            );

            let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
                enabled_mpk: enabled_mpk.clone(),
                ..Default::default()
            });
            cmd.populate_chksum().unwrap();

            let response =
                model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

            validate_ocp_lock_response(model, response, |response, _| {
                let _ = response.unwrap().unwrap();
            });
            result_mpks.push((enabled_mpk, locked_mpk));
        }
    }
    result_mpks
}

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
        let actual_mek = actual_mek.unwrap();
        assert_eq!(response.mek_checksum, EXPECTED_MEK.checksum);
        assert_eq!(actual_mek.mek, EXPECTED_MEK.mek);
    });
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_derive_mek_mix_mpk() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];

    let aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(LOCKED_MPK_TYPE.as_bytes());
        aad.extend_from_slice((metadata.len() as u32).as_bytes());
        aad.extend_from_slice(metadata.as_bytes());
        aad
    };

    let doe_out = DoeOutput::generate(&DoeInput::default());
    let mut builder = OcpLockKeyLadderBuilder::new(doe_out)
        .add_mdk()
        .add_hek([0xABDEu32; 8])
        .add_intermediate_mek_secret([0xAB; 32], [0xCD; 32]);

    for _ in 0..3 {
        let mix_mpk_cb = |mpk: &WrappedKey| {
            let mpk = builder.decrypt_locked_mpk([0xAB; 32], &access_key, &aad, &mpk.into());
            builder.mix_mpk(&mpk);
        };

        let (enabled_mpk, _) = get_enabled_mpk(
            &mut model,
            &endorsed_handle,
            &info,
            &metadata,
            &access_key,
            Some(mix_mpk_cb),
        );

        let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
            enabled_mpk,
            ..Default::default()
        });
        cmd.populate_chksum().unwrap();

        let response =
            model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

        validate_ocp_lock_response(&mut model, response, |response, _| {
            let _ = response.unwrap().unwrap();
        });
    }

    let expected_mek = builder.derive_mek();
    let mut cmd = MailboxReq::OcpLockDeriveMek(OcpLockDeriveMekReq {
        hdr: MailboxReqHeader { chksum: 0 },
        reserved: 0,
        mek_checksum: expected_mek.checksum,
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
        let actual_mek = actual_mek.unwrap();
        assert_eq!(response.mek_checksum, expected_mek.checksum);
        assert_eq!(actual_mek.mek, expected_mek.mek);
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
        let actual_mek = actual_mek.unwrap();
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
        let actual_mek = actual_mek.unwrap();
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
        let actual_mek = actual_mek.unwrap();
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
        let actual_mek = actual_mek.unwrap();
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
        let actual_mek = actual_mek.unwrap();
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

fn update_fw(model: &mut DefaultHwModel) {
    let image = caliptra_builder::build_and_sign_image(
        &FMC_FPGA_WITH_UART,
        &APP_WITH_UART_OCP_LOCK_FPGA,
        ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::MLDSA,
            ..Default::default()
        },
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();
}
