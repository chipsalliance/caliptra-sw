/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa87.rs

Abstract:

    File contains the driver-level API for ML-DSA-87 cryptographic operations.

    Caliptra 1.x silicon has no ML-DSA hardware accelerator, so this driver is a
    thin, stateless wrapper around the pure-software `caliptra-mldsa`
    implementation. It mirrors the shape of the hardware `Ecc384` driver so the
    rest of the firmware can treat ML-DSA the same way it treats ECC-384.

--*/

use crate::CaliptraResult;
use caliptra_mldsa::Mldsa87 as Mldsa87Sw;

pub use caliptra_mldsa::{
    Mldsa87Result, MLDSA87_PRIVATE_KEY_BYTES, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES,
    MLDSA87_RANDOMIZER_BYTES, MLDSA87_SIGNATURE_BYTES,
};

/// ML-DSA-87 deterministic key-generation / signing seed (32 bytes).
pub type Mldsa87Seed = [u8; MLDSA87_PRIVATE_SEED_BYTES];

/// ML-DSA-87 encoded public key (2,592 bytes).
pub type Mldsa87PubKey = [u8; MLDSA87_PUBLIC_KEY_BYTES];

/// ML-DSA-87 FIPS 204 encoded private key (4,896 bytes).
pub type Mldsa87PrivKey = [u8; MLDSA87_PRIVATE_KEY_BYTES];

/// ML-DSA-87 encoded signature (4,627 bytes).
pub type Mldsa87Signature = [u8; MLDSA87_SIGNATURE_BYTES];

/// Software ML-DSA-87 engine.
///
/// This is a stateless wrapper; there is no hardware to own. The methods return
/// [`CaliptraResult`] for consistency with the other crypto drivers and to keep
/// the API stable if validation (e.g. a pairwise-consistency self-test) is added
/// later. The underlying software operations are currently infallible.
///
/// Each operation is marked `#[inline(never)]` so that the large (tens of KB)
/// stack frames used by keygen and signing do not get inlined into — and
/// coexist with — their callers. This is important on RT where the 85 KB stack
/// is tight for ML-DSA signing.
pub struct Mldsa87;

impl Mldsa87 {
    /// Deterministically derive the ML-DSA-87 public key from a 32-byte seed,
    /// optionally also producing the FIPS 204 encoded private key (`skEncode`)
    /// in the same key generation.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte private seed
    /// * `pub_key` - Buffer that receives the encoded public key
    /// * `priv_key` - Optional buffer; if supplied, receives the encoded private
    ///   key. Passing `None` skips private-key encoding entirely.
    #[inline(never)]
    pub fn pub_from_seed(
        seed: &Mldsa87Seed,
        pub_key: &mut Mldsa87PubKey,
        priv_key: Option<&mut Mldsa87PrivKey>,
    ) -> CaliptraResult<()> {
        match priv_key {
            Some(priv_key) => Mldsa87Sw::key_pair_from_seed(seed, pub_key, priv_key),
            None => Mldsa87Sw::pub_from_seed(seed, pub_key),
        }
        Ok(())
    }

    /// Deterministically sign `msg` with the key derived from `seed`.
    ///
    /// Determinism (no per-signature randomizer) means the same seed and message
    /// always produce the same signature, which is what lets the CSR and DPE
    /// artifacts be regenerated on demand instead of being stored.
    ///
    /// # Arguments
    ///
    /// * `seed` - 32-byte private seed
    /// * `msg` - Message to sign
    /// * `sig` - Buffer that receives the encoded signature
    #[inline(never)]
    pub fn sign_deterministic(
        seed: &Mldsa87Seed,
        msg: &[u8],
        sig: &mut Mldsa87Signature,
    ) -> CaliptraResult<()> {
        Mldsa87Sw::sign_deterministic(seed, msg, sig);
        Ok(())
    }

    /// Verify an ML-DSA-87 signature over `msg`.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Encoded public key
    /// * `sig` - Encoded signature
    /// * `msg` - Message that was signed
    ///
    /// # Returns
    ///
    /// [`Mldsa87Result::Success`] if the signature is valid, otherwise
    /// [`Mldsa87Result::SigVerifyFailed`].
    #[inline(never)]
    pub fn verify(
        pub_key: &Mldsa87PubKey,
        sig: &Mldsa87Signature,
        msg: &[u8],
    ) -> CaliptraResult<Mldsa87Result> {
        Ok(Mldsa87Sw::verify(pub_key, sig, msg))
    }

    /// Verify an ML-DSA-87 signature over `msg` using an explicit signing
    /// `context`.
    ///
    /// [`Self::verify`] is equivalent to this with an empty context. This entry
    /// point exists so the FIPS known-answer test can drive the NIST ACVP
    /// signature-verification vectors, which use a non-empty context.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Encoded public key
    /// * `sig` - Encoded signature
    /// * `msg` - Message that was signed
    /// * `context` - Signing context (domain separator)
    ///
    /// # Returns
    ///
    /// [`Mldsa87Result::Success`] if the signature is valid, otherwise
    /// [`Mldsa87Result::SigVerifyFailed`].
    #[inline(never)]
    pub fn verify_with_context(
        pub_key: &Mldsa87PubKey,
        sig: &Mldsa87Signature,
        msg: &[u8],
        context: &[u8],
    ) -> CaliptraResult<Mldsa87Result> {
        Ok(Mldsa87Sw::verify_with_context(pub_key, sig, msg, context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Mldsa87Seed = [0x42; MLDSA87_PRIVATE_SEED_BYTES];

    #[test]
    fn test_keygen_deterministic() {
        let mut pk1 = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        let mut pk2 = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        Mldsa87::pub_from_seed(&SEED, &mut pk1, None).unwrap();
        Mldsa87::pub_from_seed(&SEED, &mut pk2, None).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        Mldsa87::pub_from_seed(&SEED, &mut pk, None).unwrap();

        let msg = b"caliptra pqc mldsa-87 driver round-trip";
        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        Mldsa87::sign_deterministic(&SEED, msg, &mut sig).unwrap();

        assert_eq!(
            Mldsa87::verify(&pk, &sig, msg).unwrap(),
            Mldsa87Result::Success
        );
    }

    #[test]
    fn test_sign_is_deterministic() {
        let msg = b"deterministic signing";
        let mut sig1 = [0u8; MLDSA87_SIGNATURE_BYTES];
        let mut sig2 = [0u8; MLDSA87_SIGNATURE_BYTES];
        Mldsa87::sign_deterministic(&SEED, msg, &mut sig1).unwrap();
        Mldsa87::sign_deterministic(&SEED, msg, &mut sig2).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        Mldsa87::pub_from_seed(&SEED, &mut pk, None).unwrap();

        let msg = b"tamper detection";
        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        Mldsa87::sign_deterministic(&SEED, msg, &mut sig).unwrap();
        sig[0] ^= 0xFF;

        assert_eq!(
            Mldsa87::verify(&pk, &sig, msg).unwrap(),
            Mldsa87Result::SigVerifyFailed
        );
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let mut pk = [0u8; MLDSA87_PUBLIC_KEY_BYTES];
        Mldsa87::pub_from_seed(&SEED, &mut pk, None).unwrap();

        let mut sig = [0u8; MLDSA87_SIGNATURE_BYTES];
        Mldsa87::sign_deterministic(&SEED, b"message one", &mut sig).unwrap();

        assert_eq!(
            Mldsa87::verify(&pk, &sig, b"message two").unwrap(),
            Mldsa87Result::SigVerifyFailed
        );
    }
}
