// Licensed under the Apache-2.0 license

#![cfg_attr(not(test), no_std)]

use crate::mldsa87::{
    mldsa87_pub_from_seed, mldsa87_sign, mldsa87_sign_deterministic, mldsa87_verify,
};
pub use crate::mldsa87::{
    MLDSA87_PRIVATE_SEED_BYTES, MLDSA87_PUBLIC_KEY_BYTES, MLDSA87_RANDOMIZER_BYTES,
    MLDSA87_SIGNATURE_BYTES,
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
    ) -> bool {
        mldsa87_verify(pub_key, sig, msg)
    }
}

#[cfg(test)]
mod acvp;
