// Licensed under the Apache-2.0 license

use std::sync::LazyLock;

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, OcpLockGenerateMpkResp, OcpLockRewrapMpkResp,
    OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;
use caliptra_test::derive::{DoeInput, DoeOutput, OcpLockKeyLadderBuilder};

use super::{
    boot_ocp_lock_runtime, create_generate_mpk_req, create_rewrap_mpk_req,
    get_validated_hpke_handle, validate_ocp_lock_response, OcpLockBootParams,
};

use zerocopy::{FromBytes, IntoBytes};

const WRAPPED_MEK_TYPE: u16 = 0x1;

static KEY_LADDER: LazyLock<OcpLockKeyLadderBuilder> = LazyLock::new(|| {
    // Match the input params for the OCP LOCK Key ladder
    // * Same UDS / FE
    // * Same HEK
    // * Same DPK / SEK
    let doe_out = DoeOutput::generate(&DoeInput::default());
    OcpLockKeyLadderBuilder::new(doe_out).add_hek([0xABDEu32; 8])
});

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_rewrap_mpk() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let endorsed_handle = get_validated_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
    )
    .unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];
    let cmd = create_generate_mpk_req(&endorsed_handle, &info, &metadata, &access_key);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    let wrapped_key = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        response.wrapped_mek.clone()
    })
    .unwrap();

    let aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(WRAPPED_MEK_TYPE.as_bytes());
        aad.extend_from_slice((metadata.len() as u32).as_bytes());
        aad.extend_from_slice(metadata.as_bytes());
        aad
    };

    let mpk1 = KEY_LADDER.decrypt_locked_mpk([0xAB; 32], &access_key, &aad, &(&wrapped_key).into());

    let new_access_key = [0xCD; 32];
    let cmd = create_rewrap_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &new_access_key,
        &wrapped_key,
    );
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_REWRAP_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    let wrapped_key = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockRewrapMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        response.wrapped_mek.clone()
    })
    .unwrap();
    let mpk2 =
        KEY_LADDER.decrypt_locked_mpk([0xAB; 32], &new_access_key, &aad, &(&wrapped_key).into());
    assert_eq!(mpk1, mpk2);
}

#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_rewrap_invalid_hpke_key() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let mut endorsed_handle = get_validated_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
    )
    .unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];
    let cmd = create_generate_mpk_req(&endorsed_handle, &info, &metadata, &access_key);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    let wrapped_key = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        response.wrapped_mek.clone()
    })
    .unwrap();

    // Scramble pub key so shared secret is incorrect.
    endorsed_handle.pub_key[5..10].clone_from_slice(&[0xAA; 5]);

    let new_access_key = [0xCD; 32];
    let cmd = create_rewrap_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &new_access_key,
        &wrapped_key,
    );
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_REWRAP_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG.into(),)
        );
    });
}
