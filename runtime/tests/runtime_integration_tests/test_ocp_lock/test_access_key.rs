// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, MailboxReq, OcpLockGenerateMpkResp, OcpLockTestAccessKeyReq,
    OcpLockTestAccessKeyResp, SealedAccessKey, WrappedKey, OCP_LOCK_MAX_ENC_LEN,
    OCP_LOCK_WRAPPED_KEY_MAX_INFO_LEN, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::HwModel;
use openssl::sha::sha384;

use super::{
    boot_ocp_lock_runtime, create_generate_mpk_req, encrypt_message_to_hpke_pub_key,
    get_validated_hpke_handle, validate_ocp_lock_response, OcpLockBootParams, ValidatedHpkeHandle,
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
