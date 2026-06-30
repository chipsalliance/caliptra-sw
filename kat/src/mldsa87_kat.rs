/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa87_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for ML-DSA-87.

--*/

use caliptra_drivers::{
    Array4x12, CaliptraError, CaliptraResult, Mldsa87, Mldsa87PrivKey, Mldsa87PubKey,
    Mldsa87Result, Mldsa87Seed, Mldsa87Signature, Sha384,
};

// Digest-based KAT, mirroring the Caliptra 2.x / `main` ML-DSA KAT format and
// adapted to the 1.x software implementation. Instead of embedding the full key
// pair (public key 2,592 B, private key 4,896 B) and signature (4,627 B), only
// their SHA-384 digests (48 B each) are stored; the artifacts are regenerated
// from a seed at runtime and compared by digest. This keeps the KAT's
// instruction-memory footprint small (~7 KB smaller than embedding the values).
//
// `SEED` is NIST ACVP ML-DSA-keyGen-FIPS204 tcId 51: both the derived public and
// private keys are the NIST known answers (the encoded private key matches the
// vector's `sk` byte-for-byte). See common/crypto/mldsa/src/acvp. The signature
// is the FIPS 204 deterministic signature over `MESSAGE` with an empty context.

const SEED: Mldsa87Seed = Mldsa87Seed::new([
    0xf7, 0x05, 0x2f, 0xbb, 0x92, 0x17, 0x59, 0xcd, 0x87, 0x16, 0x77, 0x3b, 0xa6, 0x35, 0x56, 0x30,
    0x12, 0x1d, 0x69, 0x27, 0x89, 0x9f, 0xdd, 0xa5, 0x76, 0x8e, 0x2b, 0xc2, 0x40, 0xfc, 0xcb, 0x7b,
]);

const MESSAGE: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

// FIPS 140-3 IG 10.3.A General Note 7 permits a KAT to compare a hash of the
// calculated output against a hash of the known expected output using an
// approved hash function. The digests below (big-endian words) are SHA-384 of
// the regenerated public key, private key, and signature respectively.
const PUB_KEY_DIGEST: Array4x12 = Array4x12::new([
    0x40ba0421, 0x55b5ee75, 0x2b362b99, 0x6948da14, 0xfb2d2e78, 0xf6695f6a, 0x827be8fd, 0xdad06da3,
    0xe835de7e, 0x4a3de2f7, 0xdb0eb835, 0x03265d9f,
]);

const PRIV_KEY_DIGEST: Array4x12 = Array4x12::new([
    0xc6d84bbc, 0x043e0157, 0xcf1741a1, 0x641b6865, 0xcfa3a867, 0x7423f4cc, 0xe1cbc151, 0xe5737c08,
    0x9e9dc736, 0x16d1f8d3, 0xd0e4611a, 0xc1720b08,
]);

const SIGNATURE_DIGEST: Array4x12 = Array4x12::new([
    0x1c083a52, 0xc24aaedc, 0xdfb68c9e, 0x4cedd2e3, 0xab33d288, 0x60b9e85d, 0x6bd2ec59, 0xab019ec9,
    0x1cb8ec31, 0x8cc1209c, 0xff479679, 0xfc2d7afa,
]);

#[derive(Default, Debug)]
pub struct Mldsa87Kat {}

impl Mldsa87Kat {
    /// Executes the Known Answer Tests for ML-DSA-87 covering KeyGen, SigGen and
    /// SigVer.
    ///
    /// Test vector source:
    /// NIST ACVP ML-DSA-keyGen-FIPS204 tcId 51; deterministic signature per
    /// FIPS 204.
    ///
    /// # Arguments
    ///
    /// * `sha384` - SHA2-384 driver, used to digest the regenerated artifacts
    pub fn execute(&self, sha384: &mut Sha384) -> CaliptraResult<()> {
        let public_key = Self::kat_keygen(sha384)?;
        let signature = Self::kat_sign(sha384)?;
        Self::kat_verify(&public_key, &signature)
    }

    /// KeyGen CAST: derive the ML-DSA-87 key pair from the fixed `SEED` and
    /// compare SHA-384 digests of the public and private keys against
    /// `PUB_KEY_DIGEST` and `PRIV_KEY_DIGEST`.
    #[inline(never)]
    fn kat_keygen(sha384: &mut Sha384) -> CaliptraResult<Mldsa87PubKey> {
        // A single key generation produces both the public key and the encoded
        // private key (the optional sk buffer is supplied).
        let mut public_key = Mldsa87PubKey::default();
        let mut private_key = Mldsa87PrivKey::default();
        Mldsa87::pub_from_seed(&SEED, &mut public_key, Some(&mut private_key))
            .map_err(|_| CaliptraError::KAT_MLDSA87_KEY_PAIR_GENERATE_FAILURE)?;

        let pub_key_digest = sha384
            .digest(public_key.as_slice())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;
        let priv_key_digest = sha384
            .digest(private_key.as_slice())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;

        if pub_key_digest != PUB_KEY_DIGEST || priv_key_digest != PRIV_KEY_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_KEY_PAIR_VERIFY_FAILURE)?;
        }

        Ok(public_key)
    }

    /// SigGen CAST: deterministically sign the fixed `MESSAGE` with the key
    /// derived from `SEED` and compare the SHA-384 digest of the signature
    /// against `SIGNATURE_DIGEST`.
    #[inline(never)]
    fn kat_sign(sha384: &mut Sha384) -> CaliptraResult<Mldsa87Signature> {
        let mut signature = Mldsa87Signature::default();
        Mldsa87::sign_deterministic(&SEED, &MESSAGE, &mut signature)
            .map_err(|_| CaliptraError::KAT_MLDSA87_SIGNATURE_GENERATE_FAILURE)?;

        let signature_digest = sha384
            .digest(signature.as_slice())
            .map_err(|_| CaliptraError::KAT_SHA384_DIGEST_FAILURE)?;
        if signature_digest != SIGNATURE_DIGEST {
            Err(CaliptraError::KAT_MLDSA87_SIGNATURE_MISMATCH)?;
        }

        Ok(signature)
    }

    /// SigVer CAST: verify `signature` against `public_key` and `MESSAGE`.
    #[inline(never)]
    fn kat_verify(public_key: &Mldsa87PubKey, signature: &Mldsa87Signature) -> CaliptraResult<()> {
        if Mldsa87::verify(public_key, signature, &MESSAGE)? != Mldsa87Result::Success {
            Err(CaliptraError::KAT_MLDSA87_SIGNATURE_VERIFY_FAILURE)?;
        }
        Ok(())
    }
}
