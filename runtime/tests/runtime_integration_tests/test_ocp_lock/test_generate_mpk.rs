// Licensed under the Apache-2.0 license

use std::sync::LazyLock;

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, OcpLockGenerateMpkResp, WrappedKey,
    OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;
use caliptra_test::derive::{DoeInput, DoeOutput, OcpLockKeyLadderBuilder};

use super::{
    boot_ocp_lock_runtime, create_generate_mpk_req, get_validated_hpke_handle,
    validate_ocp_lock_response, OcpLockBootParams,
};

use zerocopy::{FromBytes, IntoBytes};

const WRAPPED_MEK_TYPE: u16 = 0x1;
const WRAPPED_KEY_LEN: u32 = 32;

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
fn test_generate_mpk() {
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.wrapped_mek, &access_key, &metadata);
    });
}

// TODO(clundin): Update default HEK / pass in explicitly to make pass on emu.
#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_generate_mpk_invalid_hpke_key() {
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

    // Scramble pub key so shared secret is incorrect.
    endorsed_handle.pub_key[5..10].clone_from_slice(&[0xAA; 5]);

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];
    let cmd = create_generate_mpk_req(&endorsed_handle, &info, &metadata, &access_key);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG.into(),)
        );
    });
}

// TODO(clundin): Update default HEK / pass in explicitly to make pass on emu.
#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_generate_mpk_missing_hek() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: false,
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_HEK_UNAVAILABLE.into(),)
        );
    });
}

// TODO(clundin): Debug why RT public key changes during warm reset on emulator.
#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_generate_mpk_warm_reset() {
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

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.wrapped_mek, &access_key, &metadata);
    })
    .unwrap();

    model.warm_reset_flow().unwrap();

    let endorsed_handle = get_validated_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
    )
    .unwrap();

    let cmd = create_generate_mpk_req(&endorsed_handle, &info, &metadata, &access_key);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.wrapped_mek, &access_key, &metadata);
    });
}

fn validate_wrapped_key(key: &WrappedKey, access_key: &[u8; 32], metadata: &[u8]) -> [u8; 32] {
    let aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(WRAPPED_MEK_TYPE.as_bytes());
        aad.extend_from_slice((metadata.len() as u32).as_bytes());
        aad.extend_from_slice(metadata.as_bytes());
        aad
    };
    // Make sure that we can decrypt the MPK, so the AAD & Encryption Key is what we expect.
    let mpk = KEY_LADDER.decrypt_mpk([0xAB; 32], access_key, &aad, &key.into());
    assert_eq!(key.key_type, WRAPPED_MEK_TYPE);
    assert_ne!(key.salt, [0; 12]);
    assert_ne!(key.iv, [0; 12]);
    assert_ne!(key.cipher_text_and_auth_tag, [0; 80]);
    assert_eq!(key.metadata_len, metadata.len() as u32);
    assert_eq!(key.key_len, WRAPPED_KEY_LEN);
    assert_eq!(&key.metadata, &metadata);
    mpk
}
