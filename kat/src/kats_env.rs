// Licensed under the Apache-2.0 license

#[cfg(feature = "rom")]
use caliptra_drivers::AesGcm;
#[cfg(not(feature = "rom"))]
use caliptra_drivers::{Aes, MlKem1024};
use caliptra_drivers::{
    Ecc384, Hmac, Lms, Mldsa87, Sha256, Sha2_512_384, Sha2_512_384Acc, Sha3, ShaAccLockState, Trng,
};

pub struct KatsEnv<'a, 'b> {
    // SHA2-256 Engine
    pub sha256: &'a mut Sha256,

    // SHA2-512/384 Engine
    pub sha2_512_384: &'a mut Sha2_512_384,

    // SHA2-512/384 Accelerator
    pub sha2_512_384_acc: &'a mut Sha2_512_384Acc,

    // SHA3/SHAKE Engine
    pub sha3: &'a mut Sha3,

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

    /// MLDSA Engine
    pub mldsa87: &'a mut Mldsa87<'b>,

    /// AES-GCM Engine (for ROM builds - provides access to GCM and CMAC-KDF KATs)
    #[cfg(feature = "rom")]
    pub aes_gcm: &'a mut AesGcm,

    /// AES Engine (for non-ROM builds - provides access to all AES KATs)
    #[cfg(not(feature = "rom"))]
    pub aes: &'a mut Aes,

    #[cfg(not(feature = "rom"))]
    pub mlkem1024: Option<&'a mut MlKem1024<'b>>,
}
