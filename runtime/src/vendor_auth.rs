/*++

Licensed under the Apache-2.0 license.

File Name:

    vendor_auth.rs

Abstract:

    Vendor-unique command authentication. Per-command challenge/response modeled on
    production debug-unlock: HELLO mints a one-time nonce; CHALLENGE hybrid-verifies
    (ECDSA-P384 + ML-DSA-87) over cmd_id ‖ body_hash ‖ nonce against the anchor
    enrolled at SET_AUTH_MANIFEST (FwPersistentData::vendor_cmd_pk_hash).

--*/

use crate::mutrefbytes;
use caliptra_cfi_lib::{cfi_assert_eq_12_words, cfi_launder, CfiCounter};
use caliptra_common::mailbox_api::{
    VendorAuthChallengeReq, VendorAuthChallengeResp, VendorAuthHelloResp, VENDOR_AUTH_NONCE_SIZE,
};
use caliptra_drivers::{
    sha2_512_384::Sha2DigestOpTrait, Array4x12, Array4x16, CaliptraError, CaliptraResult, Ecc384,
    Ecc384PubKey, Ecc384Result, Ecc384Scalar, Ecc384Signature, LEArray4x16, Mldsa87, Mldsa87PubKey,
    Mldsa87Result, Mldsa87Signature, Sha2_512_384, Trng,
};
use zerocopy::{FromBytes, IntoBytes};

/// Runtime state for vendor-unique command authentication.
#[derive(Default)]
pub struct VendorAuth {
    /// The last minted one-time nonce, consumed on the next VENDOR_AUTH_CHALLENGE.
    last_challenge: Option<[u8; VENDOR_AUTH_NONCE_SIZE]>,
}

impl VendorAuth {
    pub fn new() -> Self {
        Self {
            last_challenge: None,
        }
    }

    /// Handle VENDOR_AUTH_HELLO: mint a fresh one-time nonce, store it, and return it.
    pub fn handle_hello(
        &mut self,
        trng: &mut Trng,
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        // TRNG generate() yields an Array4x12 (48 bytes).
        let nonce: [u8; VENDOR_AUTH_NONCE_SIZE] = trng
            .generate()?
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        self.last_challenge = Some(nonce);

        let resp = mutrefbytes::<VendorAuthHelloResp>(resp)?;
        *resp = VendorAuthHelloResp {
            hdr: Default::default(),
            challenge: nonce,
        };
        Ok(core::mem::size_of::<VendorAuthHelloResp>())
    }

    /// Consume and return the outstanding nonce, if any (one-time use).
    pub fn take_challenge(&mut self) -> Option<[u8; VENDOR_AUTH_NONCE_SIZE]> {
        self.last_challenge.take()
    }

    /// Handle VENDOR_AUTH_CHALLENGE: hybrid-verify against the enrolled anchor
    /// (`enrolled_pk_hash` = FwPersistentData::vendor_cmd_pk_hash) and the one-time nonce;
    /// on success echo (cmd_id, body_hash). Modeled on validate_debug_unlock_token.
    pub fn handle_challenge(
        &mut self,
        sha2_512_384: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        mldsa87: &mut Mldsa87,
        enrolled_pk_hash: &[u8; 48],
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let req = VendorAuthChallengeReq::read_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        // Random delay for CFI glitch protection (mirrors debug-unlock handle_token).
        CfiCounter::delay();

        // (A) Consume the one-time nonce and require an exact match (freshness).
        let nonce = self
            .take_challenge()
            .ok_or(CaliptraError::RUNTIME_VENDOR_AUTH_NONCE_MISMATCH)?;
        if req.challenge != nonce {
            return Err(CaliptraError::RUNTIME_VENDOR_AUTH_NONCE_MISMATCH);
        }

        // (B) SHA-384(pubkeys) must match the enrolled anchor. Word-level Array4x12 compare
        // with CFI hardening (like debug-unlock), not a byte-slice compare (endianness-safe).
        let pub_keys_digest = {
            let mut digest = Array4x12::default();
            let mut op = sha2_512_384.sha384_digest_init()?;
            op.update(req.ecc_public_key.as_bytes())?;
            op.update(req.mldsa_public_key.as_bytes())?;
            op.finalize(&mut digest)?;
            digest
        };
        let enrolled_digest = Array4x12::from(enrolled_pk_hash);
        if cfi_launder(pub_keys_digest) != enrolled_digest {
            return Err(CaliptraError::RUNTIME_VENDOR_AUTH_WRONG_PUBLIC_KEYS);
        } else {
            cfi_assert_eq_12_words(&pub_keys_digest.0, &enrolled_digest.0);
        }

        // Signed message = cmd_id(BE,4) ‖ body_hash(48) ‖ nonce(48). No domain separator
        // (mirrors prod-debug-unlock). ECC uses SHA-384; ML-DSA uses SHA-512 -> LE.
        let cmd_id_be = req.cmd_id.to_be_bytes();

        // (C) ECC P-384 verify.
        let ecc_pubkey = Ecc384PubKey {
            x: Ecc384Scalar::from(<[u32; 12]>::try_from(&req.ecc_public_key[..12]).unwrap()),
            y: Ecc384Scalar::from(<[u32; 12]>::try_from(&req.ecc_public_key[12..]).unwrap()),
        };
        let ecc_sig = Ecc384Signature {
            r: Ecc384Scalar::from(<[u32; 12]>::try_from(&req.ecc_signature[..12]).unwrap()),
            s: Ecc384Scalar::from(<[u32; 12]>::try_from(&req.ecc_signature[12..]).unwrap()),
        };
        let mut ecc_msg = Array4x12::default();
        {
            let mut op = sha2_512_384.sha384_digest_init()?;
            op.update(&cmd_id_be)?;
            op.update(&req.body_hash)?;
            op.update(&req.challenge)?;
            op.finalize(&mut ecc_msg)?;
        }
        if ecc384.verify(&ecc_pubkey, &ecc_msg, &ecc_sig)? == Ecc384Result::SigVerifyFailed {
            return Err(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE);
        }

        // (D) ML-DSA-87 verify (SHA-512 message, little-endian for the engine).
        let mut mldsa_msg = Array4x16::default();
        {
            let mut op = sha2_512_384.sha512_digest_init()?;
            op.update(&cmd_id_be)?;
            op.update(&req.body_hash)?;
            op.update(&req.challenge)?;
            op.finalize(&mut mldsa_msg)?;
        }
        let mldsa_msg: LEArray4x16 = mldsa_msg.into();
        let mldsa_result = mldsa87.verify_var(
            &Mldsa87PubKey::from(&req.mldsa_public_key),
            mldsa_msg.as_bytes(),
            &Mldsa87Signature::from(&req.mldsa_signature),
        )?;
        if mldsa_result == Mldsa87Result::SigVerifyFailed {
            return Err(CaliptraError::RUNTIME_VENDOR_AUTH_INVALID_SIGNATURE);
        }

        // (E) Both passed (strict-AND). Echo (cmd_id, body_hash) for TOCTOU binding.
        let resp = mutrefbytes::<VendorAuthChallengeResp>(resp)?;
        *resp = VendorAuthChallengeResp {
            hdr: Default::default(),
            cmd_id: req.cmd_id,
            body_hash: req.body_hash,
        };
        Ok(core::mem::size_of::<VendorAuthChallengeResp>())
    }
}
