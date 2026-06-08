// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]

use crate::mldsa87::{
    mldsa87_key_pair_from_seed, mldsa87_pub_from_seed, mldsa87_sign, mldsa87_sign_deterministic,
    mldsa87_verify, mldsa87_verify_with_context,
};
pub use crate::mldsa87::{
    Mldsa87Result, MLDSA87_PRIVATE_KEY_BYTES, MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES,
    MLDSA87_RANDOMIZER_BYTES, MLDSA87_SIGNATURE_BYTES,
};

mod ct;
mod mldsa87;

pub struct Mldsa87;

impl Mldsa87 {
    pub fn pub_from_seed(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        pub_key: &mut [u8; MLDSA87_PUBLIC_KEY_BYTES],
    ) {
        mldsa87_pub_from_seed(pub_key, seed)
    }

    /// Deterministically derive both the encoded public key and the FIPS 204
    /// encoded private key (`skEncode`) from a 32-byte seed, in one key
    /// generation.
    pub fn key_pair_from_seed(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        pub_key: &mut [u8; MLDSA87_PUBLIC_KEY_BYTES],
        priv_key: &mut [u8; MLDSA87_PRIVATE_KEY_BYTES],
    ) {
        mldsa87_key_pair_from_seed(pub_key, priv_key, seed)
    }

    pub fn sign(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
        msg: &[u8],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign(sig, seed, randomizer, msg);
    }

    pub fn sign_deterministic(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        msg: &[u8],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_deterministic(sig, seed, msg);
    }

    pub fn verify(
        pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
        sig: &[u8; MLDSA87_SIGNATURE_BYTES],
        msg: &[u8],
    ) -> Mldsa87Result {
        mldsa87_verify(pub_key, sig, msg)
    }

    /// Verify a signature using an explicit signing `context`.
    ///
    /// [`Self::verify`] is equivalent to this with an empty context. This entry
    /// point exists so the NIST ACVP sigVer known-answer vectors (which use a
    /// non-empty context) can be driven directly, e.g. by the FIPS KAT.
    pub fn verify_with_context(
        pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
        sig: &[u8; MLDSA87_SIGNATURE_BYTES],
        msg: &[u8],
        context: &[u8],
    ) -> Mldsa87Result {
        mldsa87_verify_with_context(pub_key, sig, msg, context)
    }
}

#[cfg(test)]
mod acvp;
