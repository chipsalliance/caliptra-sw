// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, MailboxReq, OcpLockEnableMpkResp, OcpLockGenerateMpkResp,
    WrappedKey, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;

use super::{
    assert_hpke_key_rotated, boot_ocp_lock_runtime, create_enable_mpk_req, create_generate_mpk_req,
    get_all_validated_hpke_handles, get_hpke_handle, get_validated_hpke_handle,
    validate_ocp_lock_response, verify_hpke_pub_key, OcpLockBootParams,
};

use zerocopy::{FromBytes, IntoBytes};

const WRAPPED_MEK_TYPE: u16 = 0x2;
const WRAPPED_KEY_LEN: u32 = 32;

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_enable_mpk() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

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

    let cmd = create_enable_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
    );

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockEnableMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.enabled_mpk, &metadata);
    });
}

fn validate_wrapped_key(key: &WrappedKey, metadata: &[u8]) {
    assert_eq!(key.key_type, WRAPPED_MEK_TYPE);
    assert_ne!(key.salt, [0; 12]);
    assert_ne!(key.iv, [0; 12]);
    assert_ne!(key.ciphertext_and_auth_tag, [0; 80]);
    assert_eq!(key.metadata_len, metadata.len() as u32);
    assert_eq!(key.key_len, WRAPPED_KEY_LEN);
    assert_eq!(&key.metadata, &metadata);
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_enable_mpk_invalid_locked_mpk() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

    let info = [0xDE; 256];
    let metadata = [0xFE; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN];
    let access_key = [0xAE; 32];
    let cmd = create_generate_mpk_req(&endorsed_handle, &info, &metadata, &access_key);

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_GENERATE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    let mut wrapped_key = validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        response.wrapped_mek.clone()
    })
    .unwrap();

    // Corrupt wrapped MPK ciphertext/tag
    wrapped_key.ciphertext_and_auth_tag[0] ^= 0xFF;

    let cmd = create_enable_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
    );

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(CaliptraError::RUNTIME_OCP_LOCK_LOCKED_MPK_INVALID.into(),)
        );
    });
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_enable_mpk_modified_ml_kem_enc() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    for suite in [
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
        HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM,
    ] {
        let old_handles = get_all_validated_hpke_handles(&mut model);
        let handle = get_hpke_handle(&mut model, suite).unwrap();
        let endorsed_handle = verify_hpke_pub_key(&mut model, handle).unwrap();

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

        let mut cmd = create_enable_mpk_req(
            &endorsed_handle,
            &info,
            &metadata,
            &access_key,
            &wrapped_key,
        );

        if let MailboxReq::OcpLockEnableMpk(ref mut req) = cmd {
            // Modify the ML-KEM `enc` (kem_ciphertext) to trigger FIPS 203 implicit rejection
            // during decapsulation and cause HPKE `open()` to fail.
            req.sealed_access_key.kem_ciphertext[0] ^= 0xFF;
        }
        cmd.populate_chksum().unwrap();

        let response = model.mailbox_execute(
            CommandId::OCP_LOCK_ENABLE_MPK.into(),
            cmd.as_bytes().unwrap(),
        );

        validate_ocp_lock_response(&mut model, response, |response, _| {
            assert_eq!(
                response.unwrap_err(),
                ModelError::MailboxCmdFailed(
                    CaliptraError::RUNTIME_OCP_LOCK_HPKE_KEYS_ROTATED_DUE_TO_ERROR.into(),
                )
            );
        });

        assert_hpke_key_rotated(&mut model, &old_handles, &endorsed_handle);
    }
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_enable_mpk_hybrid_modified_ml_kem_and_invalid_p384_enc() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let old_handles = get_all_validated_hpke_handles(&mut model);
    let handle = get_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_ECDH_P384_HKDF_SHA384_AES_256_GCM,
    )
    .unwrap();
    let endorsed_handle = verify_hpke_pub_key(&mut model, handle).unwrap();

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

    let mut cmd = create_enable_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
    );

    if let MailboxReq::OcpLockEnableMpk(ref mut req) = cmd {
        // Corrupt both the ML-KEM ciphertext (`kem_ciphertext[..1568]`) and the P-384 ECDH public
        // key (`kem_ciphertext[1568..1665]`) so the ECDH point is off the curve.
        req.sealed_access_key.kem_ciphertext[0] ^= 0xFF;
        req.sealed_access_key.kem_ciphertext[1568 + 9] ^= 0xFF;
    }
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_HPKE_KEYS_ROTATED_DUE_TO_ERROR.into(),
            )
        );
    });

    assert_hpke_key_rotated(&mut model, &old_handles, &endorsed_handle);
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_enable_mpk_unknown_hpke_handle() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    let old_handles = get_all_validated_hpke_handles(&mut model);
    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

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

    let mut unknown_cmd = create_enable_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
    );
    if let MailboxReq::OcpLockEnableMpk(ref mut req) = unknown_cmd {
        req.sealed_access_key.hpke_handle.handle = u32::MAX;
    }
    unknown_cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        unknown_cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        assert_eq!(
            response.unwrap_err(),
            ModelError::MailboxCmdFailed(
                CaliptraError::RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE.into(),
            )
        );
    });

    assert_eq!(old_handles, get_all_validated_hpke_handles(&mut model));

    let cmd = create_enable_mpk_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
    );
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_ENABLE_MPK.into(),
        cmd.as_bytes().unwrap(),
    );

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockEnableMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
        validate_wrapped_key(&response.enabled_mpk, &metadata);
    });
}
