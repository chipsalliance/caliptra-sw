// Licensed under the Apache-2.0 license

use caliptra_drivers::{
    Ecc384, Hmac, Lms, Sha1, Sha256, Sha2_512_384Acc, Sha384, ShaAccLockState, Trng,
};

pub struct KatsEnv<'a> {
    // SHA1 Engine
    pub sha1: &'a mut Sha1,

    // SHA2-256 Engine
    pub sha256: &'a mut Sha256,

    // SHA2-384 Engine
    pub sha384: &'a mut Sha384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: &'a mut Sha2_512_384Acc,

    /// Hmac-512/384 Engine
    pub hmac: &'a mut Hmac,

    /// Cryptographically Secure Random Number Generator
    pub trng: &'a mut Trng,

    /// LMS Engine
    pub lms: &'a mut Lms,

    /// Ecc384 Engine
    pub ecc384: &'a mut Ecc384,

    /// SHA Acc Lock State
    pub sha_acc_lock_state: ShaAccLockState,
}
