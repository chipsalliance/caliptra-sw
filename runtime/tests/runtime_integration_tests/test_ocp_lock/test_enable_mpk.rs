// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::{
    CommandId, OcpLockEnableMpkResp, OcpLockGenerateMpkResp, WrappedKey,
    OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::HwModel;

use super::{
    boot_ocp_lock_runtime, create_enable_mpk_req, create_generate_mpk_req,
    get_validated_hpke_handle, validate_ocp_lock_response, OcpLockBootParams,
};

use zerocopy::{FromBytes, IntoBytes};

const WRAPPED_MEK_TYPE: u16 = 0x2;
const WRAPPED_KEY_LEN: u32 = 32;

// TODO(clundin):
// * Verify enable mpk key can decrypt once
// * Verify VEK key DOES NOT change after warm reset.
// * Verify VEK key DOES change after cold reset.
//
// Blocked on https://github.com/chipsalliance/caliptra-sw/issues/3003 is implemented.

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
