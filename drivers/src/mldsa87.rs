/*++

Licensed under the Apache-2.0 license.

File Name:

    mldsa87.rs

Abstract:

    File contains API for MLDSA-87 Cryptography operations

--*/
#![allow(dead_code)]

use crate::{
    array::{Array4x1157, Array4x648},
    Array4x16,
};
use crate::{CaliptraResult, KeyReadArgs, Trng};

#[must_use]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsa87Result {
    Success = 0xAAAAAAAA,
    SigVerifyFailed = 0x55555555,
}

/// MLDSA-87 Public Key
pub type MlDsa87PubKey = Array4x648;

/// MLDSA-87 Signature
pub type MlDsa87Signature = Array4x1157;

/// MLDSA-87 Message (64 Bytes)
pub type MlDsa87MsgScalar = Array4x16;

/// TEMP: Placeholder for MlDsa87Reg
pub struct MlDsa87Reg {
    _priv: (),
}
impl MlDsa87Reg {
    /// # Safety
    ///
    /// Caller must ensure that all concurrent use of this
    /// peripheral in the firmware is done so in a compatible
    /// way. The simplest way to enforce this is to only call
    /// this function once.
    #[inline(always)]
    pub unsafe fn new() -> Self {
        Self { _priv: () }
    }
}
/// END - TEMP: Placeholder for MlDsa87Reg

/// MLDSA-87  API
pub struct MlDsa87 {
    mldsa87: MlDsa87Reg,
}

impl MlDsa87 {
    pub fn new(mldsa87: MlDsa87Reg) -> Self {
        Self { mldsa87 }
    }

    /// Generate MLDSA-87 Key Pair
    ///
    /// # Arguments
    ///
    /// * `seed` - Key Vault slot containing the seed for deterministic MLDSA Key Pair generation.
    /// * `trng` - TRNG driver instance.
    ///
    /// # Returns
    ///
    /// * `MlDsa87PubKey` - Generated MLDSA-87 Public Key
    pub fn key_pair(
        &mut self,
        _seed: &KeyReadArgs,
        _trng: &mut Trng,
    ) -> CaliptraResult<MlDsa87PubKey> {
        Ok(MlDsa87PubKey::default())
    }

    /// Sign the digest with specified private key. To defend against glitching
    /// attacks that could expose the private key, this function also verifies
    /// the generated signature.
    ///
    /// # Arguments
    ///
    /// * `priv_key_in` - Key Vault slot containing the seed for the private key generation.
    /// * `pub_key` - Public key to verify the signature with.
    /// * `msg` - Message to sign.
    /// * `trng` - TRNG driver instance.
    ///
    /// # Returns
    ///
    /// * `MlDsa87Signature` - Generated signature
    pub fn sign(
        &mut self,
        _priv_key_in: &KeyReadArgs,
        _pub_key: &MlDsa87PubKey,
        _msg: &MlDsa87MsgScalar,
        _trng: &mut Trng,
    ) -> CaliptraResult<MlDsa87Signature> {
        Ok(MlDsa87Signature::default())
    }

    /// Verify the signature with specified public key and message.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - Public key.
    /// * `msg` - Message to verify.
    /// * `signature` - Signature to verify.
    ///
    /// # Result
    ///
    /// *  `MlDsa87Result` - MlDsa87Result::Success if the signature verification passed else an error code.
    pub fn verify(
        &mut self,
        _pub_key: &MlDsa87PubKey,
        _msg: &MlDsa87MsgScalar,
        _signature: &MlDsa87Signature,
    ) -> CaliptraResult<MlDsa87Result> {
        Ok(MlDsa87Result::Success)
    }
}
