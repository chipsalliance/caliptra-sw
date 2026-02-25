// Licensed under the Apache-2.0 license

//! Verifies that an OCP LOCK command using SHA3 (via HPKE) invalidates
//! an in-progress CM_SHAKE256 streaming session.

use caliptra_api::mailbox::{
    CmShake256InitReq, CmShake256InitResp, CmShake256UpdateReq, CommandId, HpkeAlgorithms,
    MailboxReq, OcpLockGenerateMpkResp, OCP_LOCK_WRAPPED_KEY_MAX_METADATA_LEN,
};
use caliptra_hw_model::HwModel;

use super::{
    boot_ocp_lock_runtime, create_generate_mpk_req, get_hpke_handle, validate_ocp_lock_response,
    verify_hpke_pub_key, OcpLockBootParams,
};

use crate::common::assert_error;

use zerocopy::{FromBytes, IntoBytes};

/// Start a SHAKE256 streaming session, then execute an OCP LOCK command
/// that uses SHA3 (GENERATE_MPK via HPKE decapsulation), and verify that
/// a subsequent CM_SHAKE256_UPDATE with the original context fails.
#[test]
#[cfg_attr(feature = "fpga_realtime", ignore)]
fn test_shake256_invalidated_by_hpke_operation() {
    let mut model = boot_ocp_lock_runtime(OcpLockBootParams {
        hek_available: true,
        force_ocp_lock_en: true,
        ..Default::default()
    });

    // Step 1: Obtain a validated HPKE handle for ML-KEM specifically, since
    // ML-KEM decapsulation uses SHA3 which will invalidate the SHAKE256 session.
    let hpke_handle = get_hpke_handle(
        &mut model,
        HpkeAlgorithms::ML_KEM_1024_HKDF_SHA384_AES_256_GCM,
    )
    .unwrap();
    let endorsed_handle = verify_hpke_pub_key(&mut model, hpke_handle).unwrap();

    // Step 2: Start a SHAKE256 streaming session
    let mut req = CmShake256InitReq {
        input_size: 5,
        ..Default::default()
    };
    req.input[..5].copy_from_slice(b"hello");
    let mut init = MailboxReq::CmShake256Init(req);
    init.populate_chksum().unwrap();
    let resp_bytes = model
        .mailbox_execute(
            u32::from(CommandId::CM_SHAKE256_INIT),
            init.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Should have gotten a context");
    let resp = CmShake256InitResp::ref_from_bytes(resp_bytes.as_slice()).unwrap();
    let shake_context = resp.context;

    // Step 3: Execute GENERATE_MPK — this uses SHA3 via HPKE decapsulation,
    // which will clear the active_session_token in the SHA3 driver.
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
        let _response = OcpLockGenerateMpkResp::ref_from_bytes(response.as_bytes()).unwrap();
    });

    // Step 4: Try to UPDATE the SHAKE256 session — should fail because
    // the HPKE decapsulation used SHA3 (shake256_digest_init), which
    // cleared the active_session_token in the SHA3 driver.
    let mut req = CmShake256UpdateReq {
        context: shake_context,
        input_size: 5,
        ..Default::default()
    };
    req.input[..5].copy_from_slice(b"world");
    let mut update = MailboxReq::CmShake256Update(req);
    update.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::CM_SHAKE256_UPDATE),
            update.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CM_SHAKE256_CONTEXT_MISMATCH,
        resp,
    );
}
