// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]

use crate::mldsa87::{
    mldsa87_generate_sign_mu_deterministic, mldsa87_key_pair_from_seed, mldsa87_pub_from_seed,
    mldsa87_sign, mldsa87_sign_deterministic, mldsa87_sign_mu, mldsa87_sign_mu_deterministic,
    mldsa87_verify, mldsa87_verify_mu, mldsa87_verify_with_context,
};
#[cfg(test)]
use crate::mldsa87::{
    mldsa87_sign_mu_deterministic_from_sk, mldsa87_sign_mu_from_sk,
    mldsa87_sign_with_context_deterministic_from_sk, mldsa87_sign_with_context_from_sk,
};
pub use crate::mldsa87::{
    Mldsa87Result, MLDSA87_MU_BYTES, MLDSA87_PRIVATE_KEY_BYTES, MLDSA87_PRIVATE_SEED_BYTES,
    MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_RANDOMIZER_BYTES, MLDSA87_SIGNATURE_BYTES,
};
pub use caliptra_dpe_response_buffer::{ResponseBufError, ResponseBuffer};

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

    pub fn sign_mu(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
        mu: &[u8; MLDSA87_MU_BYTES],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_mu(sig, seed, randomizer, mu);
    }

    pub fn sign_mu_deterministic(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        mu: &[u8; MLDSA87_MU_BYTES],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_mu_deterministic(sig, seed, mu);
    }

    pub fn verify(
        pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
        sig: &[u8; MLDSA87_SIGNATURE_BYTES],
        msg: &[u8],
    ) -> Mldsa87Result {
        mldsa87_verify(pub_key, sig, msg)
    }

    pub fn verify_mu(
        pub_key: &[u8; MLDSA87_PUBLIC_KEY_BYTES],
        sig: &[u8; MLDSA87_SIGNATURE_BYTES],
        mu: &[u8; MLDSA87_MU_BYTES],
    ) -> Mldsa87Result {
        mldsa87_verify_mu(pub_key, sig, mu)
    }

    /// Sign `msg` with an explicit `context` using an encoded private key.
    ///
    /// Added to drive NIST ACVP sigGen vectors (group 5: external interface,
    /// pure preHash). Use [`Self::sign`] for production signing from a seed.
    #[cfg(test)]
    pub fn sign_with_context_from_sk(
        sk: &[u8; MLDSA87_PRIVATE_KEY_BYTES],
        randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
        msg: &[u8],
        context: &[u8],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_with_context_from_sk(sig, sk, randomizer, msg, context);
    }

    /// Deterministic variant of [`Self::sign_with_context_from_sk`].
    #[cfg(test)]
    pub fn sign_with_context_deterministic_from_sk(
        sk: &[u8; MLDSA87_PRIVATE_KEY_BYTES],
        msg: &[u8],
        context: &[u8],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_with_context_deterministic_from_sk(sig, sk, msg, context);
    }

    /// Sign a pre-computed `mu` using an encoded private key.
    ///
    /// Added to drive NIST ACVP sigGen vectors (group 11: internal interface,
    /// externalMu=true). Use [`Self::sign_mu`] for production signing from a seed.
    #[cfg(test)]
    pub fn sign_mu_from_sk(
        sk: &[u8; MLDSA87_PRIVATE_KEY_BYTES],
        randomizer: &[u8; MLDSA87_RANDOMIZER_BYTES],
        mu: &[u8; MLDSA87_MU_BYTES],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_mu_from_sk(sig, sk, randomizer, mu);
    }

    /// Deterministic variant of [`Self::sign_mu_from_sk`].
    #[cfg(test)]
    pub fn sign_mu_deterministic_from_sk(
        sk: &[u8; MLDSA87_PRIVATE_KEY_BYTES],
        mu: &[u8; MLDSA87_MU_BYTES],
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) {
        mldsa87_sign_mu_deterministic_from_sk(sig, sk, mu);
    }

    /// Generate the mu for an MLDSA operation based on the given response buffer and public key
    /// and then sign it.
    pub fn generate_sign_mu_deterministic(
        seed: &[u8; MLDSA87_PRIVATE_SEED_BYTES],
        msg: &dyn ResponseBuffer,
        msg_range: core::ops::Range<usize>,
        sig: &mut [u8; MLDSA87_SIGNATURE_BYTES],
    ) -> Result<(), ResponseBufError> {
        mldsa87_generate_sign_mu_deterministic(sig, seed, msg, msg_range)
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
