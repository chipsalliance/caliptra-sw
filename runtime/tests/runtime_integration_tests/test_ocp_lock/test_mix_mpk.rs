// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, OcpLockEnableMpkResp, OcpLockInitializeMekSecretReq, OcpLockMixMpkReq,
    WrappedKey, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};

use super::{
    boot_ocp_lock_runtime, create_enable_mpk_req, get_enabled_mpk, get_validated_hpke_handle,
    validate_ocp_lock_response, InitializeMekSecretParams, OcpLockBootParams,
};

use zerocopy::FromBytes;

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_mix_mpk() {
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
    let (enabled_mpk, _) = get_enabled_mpk(
        &mut model,
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        None::<fn(&WrappedKey)>,
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

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_mix_mpk_warm_reset() {
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
    let (enabled_mpk, locked_mpk) = get_enabled_mpk(
        &mut model,
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        None::<fn(&WrappedKey)>,
    );

    let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
        enabled_mpk: enabled_mpk.clone(),
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let _ = response.unwrap().unwrap();
    });

    model.warm_reset_flow().unwrap();

    // Need a new HPKE key & to re-initialize the MEK secret after a warm reset.
    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

    let mut cmd = MailboxReq::OcpLockInitializeMekSecret(OcpLockInitializeMekSecretReq {
        sek: [0xAB; 32],
        dpk: [0xCD; 32],
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_INITIALIZE_MEK_SECRET.into(),
        cmd.as_bytes().unwrap(),
    );
    validate_ocp_lock_response(&mut model, response, |response, _| {
        response.unwrap().unwrap();
    });

    let cmd = create_enable_mpk_req(&endorsed_handle, &info, &metadata, &access_key, &locked_mpk);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    let enabled_mpk = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockEnableMpkResp::ref_from_bytes(&response).unwrap();
        response.enabled_mpk.clone()
    })
    .unwrap();

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

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_mix_mpk_cold_reset() {
    let (enabled_mpk, _) = {
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
        get_enabled_mpk(
            &mut model,
            &endorsed_handle,
            &info,
            &metadata,
            &access_key,
            None::<fn(&WrappedKey)>,
        )
    };

    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        init_mek_secret_params: Some(InitializeMekSecretParams {
            sek: [0xAB; 32],
            dpk: [0xCD; 32],
        }),
        ..Default::default()
    });

    let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
        enabled_mpk,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_VEK_UNAVAILABLE.into())
        );
    });
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_mix_mpk_missing_init_mek_secrets() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];
    let (enabled_mpk, _) = get_enabled_mpk(
        &mut model,
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        None::<fn(&WrappedKey)>,
    );

    let mut cmd = MailboxReq::OcpLockMixMpk(OcpLockMixMpkReq {
        enabled_mpk,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();

    let response =
        model.mailbox_execute(CommandId::OCP_LOCK_MIX_MPK.into(), cmd.as_bytes().unwrap());

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED.into()
            )
        );
    });
}
