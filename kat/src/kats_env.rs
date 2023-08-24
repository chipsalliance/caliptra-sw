use caliptra_drivers::Ecc384;
use caliptra_drivers::{Hmac384, Lms, Sha1, Sha256, Sha384, Sha384Acc, Trng};

pub struct KatsEnv<'a> {
    // SHA1 Engine
    pub sha1: &'a mut Sha1,

    pub sha256: &'a mut Sha256,

    // SHA2-384 Engine
    pub sha384: &'a mut Sha384,

    // SHA2-384 Accelerator
    pub sha384_acc: &'a mut Sha384Acc,

    /// Hmac384 Engine
    pub hmac384: &'a mut Hmac384,

    /// Cryptographically Secure Random Number Generator
    pub trng: &'a mut Trng,

    /// LMS Engine
    pub lms: &'a mut Lms,

    /// Ecc384 Engine
    pub ecc384: &'a mut Ecc384,
}
