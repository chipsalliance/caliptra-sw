use crate::common::{run_rt_test_pqc, RuntimeTestArgs};
use caliptra_hw_model::{DefaultHwModel, HwModel};

use caliptra_api::mailbox::{
    CmDeriveStableKeyReq, CmDeriveStableKeyResp, CmEcdsaPublicKeyReq, CmEcdsaPublicKeyResp,
    CmEcdsaSignReq, CmEcdsaSignResp, CmEcdsaVerifyReq, CmHashAlgorithm, CmHmacKdfCounterReq,
    CmHmacKdfCounterResp, CmKeyUsage, CmMldsaPublicKeyReq, CmMldsaPublicKeyResp, CmMldsaSignReq,
    CmMldsaSignResp, CmMldsaVerifyReq, CmStableKeyType, Cmk, CommandId, MailboxReq,
    MailboxReqHeader, MailboxRespHeader, MAX_CMB_DATA_SIZE,
};

use caliptra_image_types::ECC384_SCALAR_BYTE_SIZE;

use zerocopy::{FromBytes, IntoBytes};

const TEST_MSG: &[u8] = b"cm warm reset test message";

fn cm_mldsa_public_key(model: &mut DefaultHwModel) -> Vec<u8> {
    // Derive stable key for MLDSA usage
    let cmk = derive_stable_key(model, CmKeyUsage::Mldsa, None);

    let mut req = MailboxReq::CmMldsaPublicKey(CmMldsaPublicKeyReq {
        cmk,
        ..Default::default()
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            CommandId::CM_MLDSA_PUBLIC_KEY.into(),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = CmMldsaPublicKeyResp::ref_from_bytes(resp_bytes.as_bytes()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    resp.public_key.to_vec()
}

fn cm_mldsa_sign(model: &mut DefaultHwModel, cmk: &Cmk, msg: &[u8]) -> [u8; 4628] {
    //MLDSA87_SIGNATURE_BYTE_SIZE is 4628

    // Fill fixed-size message buffer
    let mut msg_buf = [0u8; MAX_CMB_DATA_SIZE];
    msg_buf[..msg.len()].copy_from_slice(msg);

    let mut req = MailboxReq::CmMldsaSign(CmMldsaSignReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        message_size: msg.len() as u32,
        message: msg_buf,
    });

    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(CommandId::CM_MLDSA_SIGN.into(), req.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = CmMldsaSignResp::ref_from_bytes(resp_bytes.as_bytes()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    resp.signature
}

fn cm_mldsa_verify(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    msg: &[u8],
    sig: &[u8; 4628], //MLDSA87_SIGNATURE_BYTE_SIZE
) {
    let mut msg_buf = [0u8; MAX_CMB_DATA_SIZE];
    msg_buf[..msg.len()].copy_from_slice(msg);

    let mut req = MailboxReq::CmMldsaVerify(CmMldsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        signature: *sig,
        message_size: msg.len() as u32,
        message: msg_buf,
    });

    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(CommandId::CM_MLDSA_VERIFY.into(), req.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::ref_from_bytes(resp_bytes.as_slice()).unwrap();
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
}

fn cm_ecdsa_public_key(
    model: &mut DefaultHwModel,
) -> ([u8; ECC384_SCALAR_BYTE_SIZE], [u8; ECC384_SCALAR_BYTE_SIZE]) {
    // Derive stable key for ECDSA usage first
    let cmk = derive_stable_key(model, CmKeyUsage::Ecdsa, None);

    let mut req = MailboxReq::CmEcdsaPublicKey(CmEcdsaPublicKeyReq {
        cmk,
        ..Default::default()
    });
    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(
            CommandId::CM_ECDSA_PUBLIC_KEY.into(),
            req.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = CmEcdsaPublicKeyResp::ref_from_bytes(resp_bytes.as_bytes()).unwrap();

    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    (resp.public_key_x, resp.public_key_y)
}

fn cm_ecdsa_sign(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    msg: &[u8],
) -> ([u8; ECC384_SCALAR_BYTE_SIZE], [u8; ECC384_SCALAR_BYTE_SIZE]) {
    // Fill fixed-size message buffer
    let mut msg_buf = [0u8; MAX_CMB_DATA_SIZE];
    msg_buf[..msg.len()].copy_from_slice(msg);

    let mut req = MailboxReq::CmEcdsaSign(CmEcdsaSignReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        message_size: msg.len() as u32,
        message: msg_buf,
    });

    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(CommandId::CM_ECDSA_SIGN.into(), req.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = CmEcdsaSignResp::ref_from_bytes(resp_bytes.as_bytes()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    (resp.signature_r, resp.signature_s)
}

fn cm_ecdsa_verify(
    model: &mut DefaultHwModel,
    cmk: &Cmk,
    msg: &[u8],
    sig_r: &[u8; ECC384_SCALAR_BYTE_SIZE],
    sig_s: &[u8; ECC384_SCALAR_BYTE_SIZE],
) {
    let mut msg_buf = [0u8; MAX_CMB_DATA_SIZE];
    msg_buf[..msg.len()].copy_from_slice(msg);

    let mut req = MailboxReq::CmEcdsaVerify(CmEcdsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        signature_r: *sig_r,
        signature_s: *sig_s,
        message_size: msg.len() as u32,
        message: msg_buf,
    });

    req.populate_chksum().unwrap();

    let resp_bytes = model
        .mailbox_execute(CommandId::CM_ECDSA_VERIFY.into(), req.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = MailboxRespHeader::ref_from_bytes(resp_bytes.as_slice()).unwrap();
    assert_eq!(resp.fips_status, MailboxRespHeader::FIPS_STATUS_APPROVED);
}

fn derive_stable_key(model: &mut DefaultHwModel, usage: CmKeyUsage, key_size: Option<u32>) -> Cmk {
    let mut derive_request = MailboxReq::CmDeriveStableKey(CmDeriveStableKeyReq {
        key_type: CmStableKeyType::IDevId.into(),
        ..Default::default()
    });

    derive_request.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::CM_DERIVE_STABLE_KEY.into(),
            derive_request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = CmDeriveStableKeyResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let key_size = key_size.unwrap_or(match usage {
        CmKeyUsage::Aes => 32,
        CmKeyUsage::Hmac => 64,
        CmKeyUsage::Ecdsa => 48,
        CmKeyUsage::Mldsa => 32,
        _ => panic!("Unsupported key usage for stable key derivation"),
    });
    let cm_hmac_kdf = CmHmacKdfCounterReq {
        kin: resp.cmk.clone(),
        hash_algorithm: if key_size == 64 {
            CmHashAlgorithm::Sha512.into()
        } else {
            CmHashAlgorithm::Sha384.into()
        },
        key_usage: usage.into(),
        key_size,
        label_size: 0,
        ..Default::default()
    };
    let mut cm_hmac_kdf = MailboxReq::CmHmacKdfCounter(cm_hmac_kdf);
    cm_hmac_kdf.populate_chksum().unwrap();

    let response = model
        .mailbox_execute(
            CommandId::CM_HMAC_KDF_COUNTER.into(),
            cm_hmac_kdf.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let response = CmHmacKdfCounterResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert_eq!(
        resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    response.kout.clone()
}

// ----------------------
// Warm-reset test cases
// ----------------------

#[test]
fn test_cm_ecdsa_public_key_persists_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let (x_before, y_before) = cm_ecdsa_public_key(&mut model);

    model.warm_reset_flow().unwrap();

    let (x_after, y_after) = cm_ecdsa_public_key(&mut model);

    assert_eq!(
        x_before, x_after,
        "ECDSA public_key_x changed across warm reset"
    );
    assert_eq!(
        y_before, y_after,
        "ECDSA public_key_y changed across warm reset"
    );
}

#[test]
fn test_cm_ecdsa_sign_verify_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // Derive stable key for ECDSA usage before warm reset
    let cmk_before = derive_stable_key(&mut model, CmKeyUsage::Ecdsa, None);

    let (r_before, s_before) = cm_ecdsa_sign(&mut model, &cmk_before, TEST_MSG);
    cm_ecdsa_verify(&mut model, &cmk_before, TEST_MSG, &r_before, &s_before);

    // --- warm reset ---
    model.warm_reset_flow().unwrap();

    // Derive again after warm reset
    let cmk_after = derive_stable_key(&mut model, CmKeyUsage::Ecdsa, None);

    // verify Pre-reset signature shoudl still succeed
    cm_ecdsa_verify(&mut model, &cmk_after, TEST_MSG, &r_before, &s_before);

    // Also sign & verify again after warm reset
    let (r_after, s_after) = cm_ecdsa_sign(&mut model, &cmk_after, TEST_MSG);
    cm_ecdsa_verify(&mut model, &cmk_after, TEST_MSG, &r_after, &s_after);
}

#[test]
fn test_cm_ecdsa_public_key_and_sig_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let pub_before = cm_ecdsa_public_key(&mut model);

    // Derive stable ECDSA CMK before warm reset
    let cmk_before = derive_stable_key(&mut model, CmKeyUsage::Ecdsa, None);

    let (r_before, s_before) = cm_ecdsa_sign(&mut model, &cmk_before, TEST_MSG);
    cm_ecdsa_verify(&mut model, &cmk_before, TEST_MSG, &r_before, &s_before);

    model.warm_reset_flow().unwrap();

    let pub_after = cm_ecdsa_public_key(&mut model);
    assert_eq!(
        pub_before, pub_after,
        "ECDSA public key changed across warm reset"
    );

    // Derive stable ECDSA CMK again after warm reset
    let cmk_after = derive_stable_key(&mut model, CmKeyUsage::Ecdsa, None);

    // verify Pre-reset signature shoudl still succeed
    cm_ecdsa_verify(&mut model, &cmk_after, TEST_MSG, &r_before, &s_before);

    //  sign/verify again post-reset
    let (r_after, s_after) = cm_ecdsa_sign(&mut model, &cmk_after, TEST_MSG);
    cm_ecdsa_verify(&mut model, &cmk_after, TEST_MSG, &r_after, &s_after);
}

#[test]
fn test_cm_mldsa_public_key_and_sig_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let pub_before = cm_mldsa_public_key(&mut model);

    // Derive stable MLDSA CMK before warm reset
    let cmk_before = derive_stable_key(&mut model, CmKeyUsage::Mldsa, None);

    let sig_before = cm_mldsa_sign(&mut model, &cmk_before, TEST_MSG);
    cm_mldsa_verify(&mut model, &cmk_before, TEST_MSG, &sig_before);

    model.warm_reset_flow().unwrap();

    let pub_after = cm_mldsa_public_key(&mut model);
    assert_eq!(
        pub_before, pub_after,
        "MLDSA public key changed across warm reset"
    );

    // Derive stable MLDSA CMK again after warm reset
    let cmk_after = derive_stable_key(&mut model, CmKeyUsage::Mldsa, None);

    // verify Pre-reset signature shoudl still succeed
    cm_mldsa_verify(&mut model, &cmk_after, TEST_MSG, &sig_before);

    //  sign/verify again post-reset
    let sig_after = cm_mldsa_sign(&mut model, &cmk_after, TEST_MSG);
    cm_mldsa_verify(&mut model, &cmk_after, TEST_MSG, &sig_after);
}

#[test]
fn test_cm_mldsa_public_key_persists_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let pub_before = cm_mldsa_public_key(&mut model);

    model.warm_reset_flow().unwrap();

    let pub_after = cm_mldsa_public_key(&mut model);

    assert_eq!(
        pub_before, pub_after,
        "MLDSA public key changed across warm reset"
    );
}

// MLDSA sign/verify across warm reset
#[test]
fn test_cm_mldsa_sign_verify_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    // Derive stable key for MLDSA usage before warm reset
    let cmk_before = derive_stable_key(&mut model, CmKeyUsage::Mldsa, None);

    let sig_before = cm_mldsa_sign(&mut model, &cmk_before, TEST_MSG);
    cm_mldsa_verify(&mut model, &cmk_before, TEST_MSG, &sig_before);

    model.warm_reset_flow().unwrap();

    let cmk_after = derive_stable_key(&mut model, CmKeyUsage::Mldsa, None);

    // verify Pre-reset signature shoudl still succeed
    cm_mldsa_verify(&mut model, &cmk_after, TEST_MSG, &sig_before);

    //  sign/verify again post-reset
    let sig_after = cm_mldsa_sign(&mut model, &cmk_after, TEST_MSG);
    cm_mldsa_verify(&mut model, &cmk_after, TEST_MSG, &sig_after);
}

#[test]
fn test_derive_stable_key_after_warm_reset() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::test_productions_args(), Default::default());

    let key_before = derive_stable_key(&mut model, CmKeyUsage::Aes, None);

    model.warm_reset_flow().unwrap();

    let key_after = derive_stable_key(&mut model, CmKeyUsage::Aes, None);

    assert_eq!(
        key_before, key_after,
        "Stable key changed across warm reset"
    );
}
