// Licensed under the Apache-2.0 license

//! End-to-end vendor-command-auth tests (HELLO + CHALLENGE) with real ECC-P384 + ML-DSA-87
//! keys, anchor enrolled via a v2 Auth Manifest. Modeled on test_debug_unlock.rs.

use crate::common::{run_rt_test_pqc, RuntimeTestArgs};
use caliptra_api::mailbox::{
    CommandId, MailboxReqHeader, VendorAuthChallengeReq, VendorAuthChallengeResp,
    VendorAuthHelloReq, VendorAuthHelloResp,
};
use caliptra_auth_man_gen::default_test_manifest::{
    create_test_auth_manifest_with_vendor_cmd_hash, default_test_owner_fw_key_info,
    default_test_owner_man_key_info, default_test_vendor_fw_key_info,
    default_test_vendor_man_key_info,
};
use caliptra_auth_man_gen::{AuthManifestGenerator, AuthManifestGeneratorConfig};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, AUTH_MANIFEST_VERSION_V2,
};
use caliptra_common::mailbox_api::SetAuthManifestReq;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_gen::ImageGeneratorCrypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use fips204::traits::{SerDes, Signer};
use p384::ecdsa::VerifyingKey;
use rand::{rngs::StdRng, SeedableRng};
use sha2::Digest;
use zerocopy::{FromBytes, IntoBytes};

fn u8_to_u32_be(input: &[u8]) -> Vec<u32> {
    input
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect()
}
fn u8_to_u32_le(input: &[u8]) -> Vec<u32> {
    input
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

struct VendorAuthKeys {
    signing_ecc: p384::ecdsa::SigningKey,
    signing_mldsa: fips204::ml_dsa_87::PrivateKey,
    ecc_pub_hw: [u32; 24],
    mldsa_pub_hw: [u32; 648],
    anchor: [u8; 48],
}

fn gen_vendor_auth_keys() -> VendorAuthKeys {
    let signing_ecc = p384::ecdsa::SigningKey::random(&mut StdRng::from_entropy());
    let verifying_ecc = VerifyingKey::from(&signing_ecc);
    let mut ecc_pub_bytes = [0u8; 96];
    let pt = verifying_ecc.to_encoded_point(false);
    ecc_pub_bytes[..48].copy_from_slice(pt.x().unwrap());
    ecc_pub_bytes[48..].copy_from_slice(pt.y().unwrap());
    let ecc_pub_hw: [u32; 24] = u8_to_u32_be(&ecc_pub_bytes).try_into().unwrap();

    let (verifying_mldsa, signing_mldsa) = fips204::ml_dsa_87::try_keygen().unwrap();
    let mldsa_pub_bytes = verifying_mldsa.into_bytes();
    let mldsa_pub_hw: [u32; 648] = u8_to_u32_le(&mldsa_pub_bytes).try_into().unwrap();

    // Anchor = standard SHA-384 over the same bytes the device hashes (the hw-format word
    // arrays). The device reconstructs it via Array4x12::from(&bytes) (from_be_bytes) and
    // compares word-level to the hardware digest, so the manifest carries the raw digest
    // bytes (no per-word reversal — unlike the DMA/fuse debug-unlock path).
    let mut h = sha2::Sha384::new();
    h.update(ecc_pub_hw.as_bytes());
    h.update(mldsa_pub_hw.as_bytes());
    let anchor: [u8; 48] = h.finalize().into();

    VendorAuthKeys {
        signing_ecc,
        signing_mldsa,
        ecc_pub_hw,
        mldsa_pub_hw,
        anchor,
    }
}

/// Boot runtime with a v2 manifest enrolling `keys.anchor`, and SET_AUTH_MANIFEST it.
fn boot_with_enrolled_anchor(keys: &VendorAuthKeys) -> impl HwModel {
    let mcu_fw = [1u8, 2, 3, 4];
    let crypto = Crypto::default();
    let digest = caliptra_image_gen::from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: 1, // image source in request
        digest,
        ..Default::default()
    }];
    let manifest = create_test_auth_manifest_with_vendor_cmd_hash(
        metadata,
        FwVerificationPqcKeyType::MLDSA,
        1,
        keys.anchor,
        Crypto::default(),
    );

    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::MLDSA);
    model.step_until_ready_for_runtime();

    let buf = manifest.as_bytes();
    let mut slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);
    let mut cmd = caliptra_common::mailbox_api::MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("SET_AUTH_MANIFEST should succeed");
    model
}

/// Issue VENDOR_AUTH_HELLO and return the 48-byte nonce.
fn hello(model: &mut impl HwModel) -> [u8; 48] {
    let req = VendorAuthHelloReq {
        hdr: MailboxReqHeader { chksum: 0 },
    };
    let mut cmd = caliptra_common::mailbox_api::MailboxReq::VendorAuthHello(req);
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::VENDOR_AUTH_HELLO),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("HELLO should return a nonce");
    VendorAuthHelloResp::read_from_bytes(resp.as_slice())
        .unwrap()
        .challenge
}

/// Build a signed VENDOR_AUTH_CHALLENGE for (cmd_id, body_hash, nonce).
fn build_challenge(
    keys: &VendorAuthKeys,
    cmd_id: u32,
    body_hash: [u8; 48],
    nonce: [u8; 48],
) -> VendorAuthChallengeReq {
    let cmd_id_be = cmd_id.to_be_bytes();

    // ECC: SHA-384 message, signature in hw-format (big-endian words).
    let mut s384 = sha2::Sha384::new();
    s384.update(cmd_id_be);
    s384.update(body_hash);
    s384.update(nonce);
    let (ecc_sig, _) = keys
        .signing_ecc
        .sign_prehash_recoverable(s384.finalize().as_slice())
        .unwrap();
    let ecc_signature: [u32; 24] = u8_to_u32_be(ecc_sig.to_bytes().as_slice())
        .try_into()
        .unwrap();

    // ML-DSA: SHA-512 message, signature in hw-format (little-endian words).
    let mut s512 = sha2::Sha512::new();
    s512.update(cmd_id_be);
    s512.update(body_hash);
    s512.update(nonce);
    let mldsa_sig = keys
        .signing_mldsa
        .try_sign_with_seed(&[0; 32], &s512.finalize(), &[])
        .unwrap();
    let mldsa_signature: [u32; 1157] = {
        let mut sig = [0u8; 4628];
        sig[..4627].copy_from_slice(&mldsa_sig);
        u8_to_u32_le(&sig).try_into().unwrap()
    };

    let mut req = VendorAuthChallengeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        cmd_id,
        body_hash,
        challenge: nonce,
        ecc_public_key: keys.ecc_pub_hw,
        mldsa_public_key: keys.mldsa_pub_hw,
        ecc_signature,
        mldsa_signature,
    };
    let chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::VENDOR_AUTH_CHALLENGE),
        &req.as_bytes()[4..],
    );
    req.hdr.chksum = chksum;
    req
}

fn exec_challenge(
    model: &mut impl HwModel,
    req: &VendorAuthChallengeReq,
) -> Result<VendorAuthChallengeResp, ModelError> {
    let resp = model
        .mailbox_execute(u32::from(CommandId::VENDOR_AUTH_CHALLENGE), req.as_bytes())?
        .expect("response expected");
    Ok(VendorAuthChallengeResp::read_from_bytes(resp.as_slice()).unwrap())
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_success() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let cmd_id = 0x4D43_4D53; // an example authorized command id
    let body_hash = [0x11u8; 48];
    let nonce = hello(&mut model);
    let req = build_challenge(&keys, cmd_id, body_hash, nonce);

    let resp = exec_challenge(&mut model, &req).expect("valid challenge should authenticate");
    // Echo binds the authorization to exactly this (cmd_id, body_hash).
    assert_eq!(resp.cmd_id, cmd_id);
    assert_eq!(resp.body_hash, body_hash);
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_tampered_body_rejected() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let mut req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);
    // Tamper the body_hash after signing → signature no longer covers it.
    req.body_hash[0] ^= 0xFF;
    let chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::VENDOR_AUTH_CHALLENGE),
        &req.as_bytes()[4..],
    );
    req.hdr.chksum = chksum;

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE)
    ));
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_replayed_nonce_rejected() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);
    // First use consumes the nonce.
    exec_challenge(&mut model, &req).expect("first use ok");
    // Replaying the same challenge (nonce already taken) must fail.
    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_NONCE_MISMATCH)
    ));
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_wrong_key_rejected() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    // Sign with a DIFFERENT key pair whose pubkeys won't match the enrolled anchor.
    let other = gen_vendor_auth_keys();
    let nonce = hello(&mut model);
    let req = build_challenge(&other, 0x4D43_4D53, [0x11u8; 48], nonce);

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_WRONG_PUBLIC_KEYS)
    ));
}

// Proves the hybrid strict-AND actually EXERCISES the ML-DSA path: with a valid ECC
// signature and correct pubkeys/nonce, corrupting ONLY the ML-DSA signature must still be
// rejected. (The tampered-body test above fails at the ECC gate first, so it never reaches
// ML-DSA — a no-op ML-DSA verify would pass it. This one cannot.)
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_bad_mldsa_only_rejected() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let mut req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);
    // Corrupt ONLY the ML-DSA signature; ECC sig, pubkeys, and nonce stay valid, so the ECC
    // gate and anchor/nonce checks pass and verification reaches the ML-DSA gate.
    req.mldsa_signature[0] ^= 0x01;
    let chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::VENDOR_AUTH_CHALLENGE),
        &req.as_bytes()[4..],
    );
    req.hdr.chksum = chksum;

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE)
    ));
}

// ---- Coverage-hardening tests (mirror the debug-unlock negative suite) ----

/// Recompute the mailbox checksum after mutating a request in place.
fn refresh_checksum(req: &mut VendorAuthChallengeReq) {
    req.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::VENDOR_AUTH_CHALLENGE),
        &req.as_bytes()[4..],
    );
}

/// Boot runtime WITHOUT enrolling any vendor-command anchor (no SET_AUTH_MANIFEST),
/// so FwPersistentData::vendor_cmd_pk_hash stays all-zero.
fn boot_no_anchor() -> impl HwModel {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::MLDSA);
    model.step_until_ready_for_runtime();
    model
}

/// Build a v2 manifest with NO vendor-command 0x0001 record (the enrollment gate must reject it).
fn v2_manifest_missing_vendor_hash() -> AuthorizationManifest {
    let mcu_fw = [1u8, 2, 3, 4];
    let crypto = Crypto::default();
    let digest = caliptra_image_gen::from_hw_format(&crypto.sha384_digest(&mcu_fw).unwrap());
    let metadata = vec![AuthManifestImageMetadata {
        fw_id: 2,
        flags: 1,
        digest,
        ..Default::default()
    }];
    let cfg = AuthManifestGeneratorConfig {
        vendor_fw_key_info: Some(default_test_vendor_fw_key_info()),
        vendor_man_key_info: Some(default_test_vendor_man_key_info()),
        owner_fw_key_info: Some(default_test_owner_fw_key_info()),
        owner_man_key_info: Some(default_test_owner_man_key_info()),
        image_metadata_list: metadata,
        version: AUTH_MANIFEST_VERSION_V2,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        svn: 1,
        vendor_cmd_auth_pk_hash: None,
    };
    AuthManifestGenerator::new(Crypto::default())
        .generate(&cfg)
        .unwrap()
}

// Tier 1 -------------------------------------------------------------------

// A live nonce exists (HELLO ran) but the submitted challenge value is wrong. Exercises the
// CFI-hardened nonce VALUE-compare (vendor_auth.rs:97-104) — distinct from the replay test,
// which hits the take()==None branch. Analog: test_dbg_unlock_prod_invalid_token_challenge.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_nonce_value_mismatch() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    // Mint a live nonce, then sign/submit a DIFFERENT nonce value.
    let _live = hello(&mut model);
    let wrong_nonce = [0xA5u8; 48];
    let req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], wrong_nonce);

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_NONCE_MISMATCH)
    ));
}

// A truncated request must be rejected by the zerocopy size gate (vendor_auth.rs:83-84) before
// any crypto runs. Checksum is recomputed over the truncated body so it clears the checksum gate.
// Analog: test_dbg_unlock_prod_invalid_length.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_invalid_length() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let mut req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);

    // Drop the last dword, then recompute the checksum over the truncated body.
    let full = req.as_bytes().to_vec();
    let truncated = &full[..full.len() - 4];
    req.hdr.chksum = caliptra_common::checksum::calc_checksum(
        u32::from(CommandId::VENDOR_AUTH_CHALLENGE),
        &truncated[4..],
    );
    // Re-serialize the header with the fixed checksum, then truncate again.
    let mut buf = req.as_bytes().to_vec();
    buf.truncate(buf.len() - 4);

    let err = model
        .mailbox_execute(u32::from(CommandId::VENDOR_AUTH_CHALLENGE), &buf)
        .unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)
    ));
}

// A fully-valid CHALLENGE body submitted under the WRONG command id must fail the dispatch
// checksum gate (lib.rs:739-745), proving the checksum binds body to command id.
// Analog: test_dbg_unlock_prod_wrong_cmd.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_wrong_cmd() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);

    // Same bytes, wrong command id → checksum (computed for VENDOR_AUTH_CHALLENGE) won't verify.
    let err = model.mailbox_execute(0, req.as_bytes()).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_INVALID_CHECKSUM)
    ));
}

// No anchor enrolled (no SET_AUTH_MANIFEST): a valid, fresh, correctly-signed challenge must pass
// the nonce gate and fail the anchor gate (vendor_auth.rs:117) against the all-zero
// vendor_cmd_pk_hash. Analog: test_dbg_unlock_prod_disabled_all_zeros_pk_hash.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_anchor_not_enrolled() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_no_anchor();

    let nonce = hello(&mut model);
    let req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_WRONG_PUBLIC_KEYS)
    ));
}

// Tier 2 -------------------------------------------------------------------

// Prove cmd_id is covered by the signed transcript (not just body_hash): tamper cmd_id after
// signing, recompute checksum → the ECC message preimage no longer matches → signature fails.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_tampered_cmd_id() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let mut req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);
    req.cmd_id ^= 1; // signed transcript used the original cmd_id
    refresh_checksum(&mut req);

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE)
    ));
}

// A v2 manifest missing the 0x0001 vendor-command record must be rejected at SET_AUTH_MANIFEST
// by the extract-before-commit enrollment gate (set_auth_manifest.rs:808-816).
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_set_auth_manifest_v2_missing_vendor_pk_hash_rejected() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::MLDSA);
    model.step_until_ready_for_runtime();

    let manifest = v2_manifest_missing_vendor_hash();
    let buf = manifest.as_bytes();
    let mut slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);
    let mut cmd = caliptra_common::mailbox_api::MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    let err = model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_AUTH_MANIFEST_MISSING_VENDOR_AUTH_PK_HASH)
    ));
}

// Symmetric partner to bad_mldsa_only: corrupt ONLY the ECC signature (ML-DSA sig, pubkeys, and
// nonce stay valid) and prove the ECC gate is a real verify that rejects independently.
#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
fn test_vendor_auth_challenge_bad_ecc_only_rejected() {
    let keys = gen_vendor_auth_keys();
    let mut model = boot_with_enrolled_anchor(&keys);

    let nonce = hello(&mut model);
    let mut req = build_challenge(&keys, 0x4D43_4D53, [0x11u8; 48], nonce);
    req.ecc_signature[0] ^= 0x01;
    refresh_checksum(&mut req);

    let err = exec_challenge(&mut model, &req).unwrap_err();
    assert!(matches!(
        err,
        ModelError::MailboxCmdFailed(c)
            if c == u32::from(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE)
    ));
}
