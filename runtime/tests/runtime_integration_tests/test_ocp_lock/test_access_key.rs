// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, HpkeAlgorithms, MailboxReq, OcpLockGenerateMpkResp, OcpLockTestAccessKeyReq,
    OcpLockTestAccessKeyResp, SealedAccessKey, WrappedKey, OCP_LOCK_MAX_ENC_LEN,
    OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_kat::CaliptraError;
use openssl::sha::sha384;

use super::{
    assert_hpke_key_rotated, boot_ocp_lock_runtime, create_generate_mpk_req,
    encrypt_message_to_hpke_pub_key, get_all_validated_hpke_handles, get_hpke_handle,
    get_validated_hpke_handle, validate_ocp_lock_response, verify_hpke_pub_key, OcpLockBootParams,
    ValidatedHpkeHandle,
};

use zerocopy::{FromBytes, IntoBytes};

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_test_access_key() {
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

    for nonce in [[0x11; 32], [0x12; 32], [0x31; 32]] {
        let cmd = create_test_access_key_req(
            &endorsed_handle,
            &info,
            &metadata,
            &access_key,
            &wrapped_key,
            &nonce,
        );

        let response = model.mailbox_execute(
            CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
            cmd.as_bytes().unwrap(),
        );

        let expected_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(&metadata);
            data.extend_from_slice(&access_key);
            data.extend_from_slice(&nonce);
            sha384(&data)
        };

        validate_ocp_lock_response(&mut model, response, |response, _| {
            let response = response.unwrap().unwrap();
            let response = OcpLockTestAccessKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
            assert_eq!(&response.digest, &expected_hash);
        });
    }
}

// TODO(clundin): Debug why RT public key changes during warm reset on emulator.
#[cfg_attr(not(feature = "fpga_subsystem"), ignore)]
#[test]
fn test_test_access_key_warm_reset() {
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

    model.warm_reset_flow().unwrap();

    let endorsed_handle = get_validated_hpke_handle(&mut model).unwrap();

    let nonce = [0x11; 32];
    let cmd = create_test_access_key_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
        &nonce,
    );

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
        cmd.as_bytes().unwrap(),
    );

    let expected_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(&metadata);
        data.extend_from_slice(&access_key);
        data.extend_from_slice(&nonce);
        sha384(&data)
    };

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockTestAccessKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(&response.digest, &expected_hash);
    });
}

fn create_test_access_key_req(
    endorsed_key: &ValidatedHpkeHandle,
    info: &[u8; OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN],
    metadata: &[u8; OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN],
    access_key: &[u8; 32],
    locked_mpk: &WrappedKey,
    nonce: &[u8; 32],
) -> MailboxReq {
    let (enc, ct) = encrypt_message_to_hpke_pub_key(endorsed_key, info, metadata, access_key);

    let mut kem_ciphertext = [0; OCP_LOCK_MAX_ENC_LEN];
    kem_ciphertext[..enc.len()].clone_from_slice(&enc);

    let mut ak_ciphertext = [0; 48];
    ak_ciphertext.clone_from_slice(&ct);

    let mut cmd = MailboxReq::OcpLockTestAccessKey(OcpLockTestAccessKeyReq {
        sek: [0xAB; 32],
        locked_mpk: locked_mpk.clone(),
        nonce: *nonce,
        sealed_access_key: SealedAccessKey {
            hpke_handle: endorsed_key.hpke_handle.clone(),
            access_key_len: access_key.len() as u32,
            info_len: info.len() as u32,
            info: *info,
            kem_ciphertext,
            ak_ciphertext,
            ..Default::default()
        },
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();
    cmd
}

#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_test_access_key_invalid_locked_mpk() {
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

    let nonce = [0x11; 32];
    let cmd = create_test_access_key_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
        &nonce,
    );

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
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
fn test_test_access_key_modified_ml_kem_enc() {
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

        let nonce = [0x11; 32];
        let mut cmd = create_test_access_key_req(
            &endorsed_handle,
            &info,
            &metadata,
            &access_key,
            &wrapped_key,
            &nonce,
        );

        if let MailboxReq::OcpLockTestAccessKey(ref mut req) = cmd {
            // Modify the ML-KEM `enc` (kem_ciphertext) to trigger FIPS 203 implicit rejection
            // during decapsulation and cause HPKE `open()` to fail.
            req.sealed_access_key.kem_ciphertext[0] ^= 0xFF;
        }
        cmd.populate_chksum().unwrap();

        let response = model.mailbox_execute(
            CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
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
fn test_test_access_key_hybrid_modified_ml_kem_and_invalid_p384_enc() {
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

    let nonce = [0x11; 32];
    let mut cmd = create_test_access_key_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
        &nonce,
    );

    if let MailboxReq::OcpLockTestAccessKey(ref mut req) = cmd {
        // Corrupt both the ML-KEM ciphertext (`kem_ciphertext[..1568]`) and the P-384 ECDH public
        // key (`kem_ciphertext[1568..1665]`) so the ECDH point is off the curve.
        req.sealed_access_key.kem_ciphertext[0] ^= 0xFF;
        req.sealed_access_key.kem_ciphertext[1568 + 9] ^= 0xFF;
    }
    cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
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
fn test_test_access_key_unknown_hpke_handle() {
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

    let nonce = [0x11; 32];
    let mut unknown_cmd = create_test_access_key_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
        &nonce,
    );
    if let MailboxReq::OcpLockTestAccessKey(ref mut req) = unknown_cmd {
        req.sealed_access_key.hpke_handle.handle = u32::MAX;
    }
    unknown_cmd.populate_chksum().unwrap();

    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
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

    let cmd = create_test_access_key_req(
        &endorsed_handle,
        &info,
        &metadata,
        &access_key,
        &wrapped_key,
        &nonce,
    );
    let response = model.mailbox_execute(
        CommandId::OCP_LOCK_TEST_ACCESS_KEY.into(),
        cmd.as_bytes().unwrap(),
    );

    let expected_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(&metadata);
        data.extend_from_slice(&access_key);
        data.extend_from_slice(&nonce);
        sha384(&data)
    };

    validate_ocp_lock_response(&mut model, response, |response, _| {
        let response = response.unwrap().unwrap();
        let response = OcpLockTestAccessKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
        assert_eq!(&response.digest, &expected_hash);
    });
}
