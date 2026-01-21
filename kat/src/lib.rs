/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Caliptra Known Answer Tests.

--*/

#![no_std]

mod aes256cbc_kat;
mod aes256cmac_kat;
mod aes256ctr_kat;
mod aes256ecb_kat;
mod aes256gcm_kat;
mod cmackdf_kat;
mod ecc384_kat;
mod ecdh_kat;
mod hkdf_kat;
mod hmac_kdf_kat;
mod kats_env;
mod lms_kat;
mod mldsa87_kat;
mod sha2_512_384acc_kat;
mod sha384_kat;
mod sha3_kat;
mod sha512_kat;

pub use aes256cbc_kat::Aes256CbcKat;
pub use aes256cmac_kat::Aes256CmacKat;
pub use aes256ctr_kat::Aes256CtrKat;
pub use aes256ecb_kat::Aes256EcbKat;
pub use aes256gcm_kat::Aes256GcmKat;
pub use caliptra_drivers::{CaliptraError, CaliptraResult};
pub use cmackdf_kat::CmacKdfKat;
pub use ecc384_kat::Ecc384Kat;
pub use ecdh_kat::EcdhKat;
pub use hkdf_kat::{Hkdf384Kat, Hkdf512Kat};
pub use hmac_kdf_kat::{Hmac384KdfKat, Hmac512KdfKat};
pub use kats_env::KatsEnv;
pub use lms_kat::LmsKat;
pub use mldsa87_kat::Mldsa87Kat;
pub use sha2_512_384acc_kat::Sha2_512_384AccKat;
pub use sha384_kat::Sha384Kat;
pub use sha3_kat::Shake256Kat;
pub use sha512_kat::Sha512Kat;

use caliptra_drivers::{cprintln, kats::Sha256Kat, Sha1, Sha256};
use caliptra_registers::sha256::Sha256Reg;

/// Drivers that have been initialized after KAT execution
pub struct InitializedDrivers {
    pub sha1: Sha1,
    pub sha256: Sha256,
}

impl InitializedDrivers {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that any
    /// concurrent access to these register blocks does not conflict with these
    /// drivers.
    pub unsafe fn new() -> CaliptraResult<Self> {
        Ok(InitializedDrivers {
            sha1: Sha1::new()?,
            sha256: Sha256::new(Sha256Reg::new())?,
        })
    }
}

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut KatsEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");

    // cprintln!("[kat] sha1");
    // let sha1 = Sha1::new()?;

    cprintln!("[kat] SHA2-256");
    Sha256Kat::default().execute(env.sha256)?;

    cprintln!("[kat] SHA2-384");
    Sha384Kat::default().execute(env.sha2_512_384)?;

    cprintln!("[kat] SHA2-512");
    Sha512Kat::default().execute(env.sha2_512_384)?;

    cprintln!("[kat] SHA2-512-ACC");
    Sha2_512_384AccKat::default().execute(env.sha2_512_384_acc, env.sha_acc_lock_state)?;

    cprintln!("[kat] SHAKE-256");
    Shake256Kat::default().execute(env.sha3)?;

    cprintln!("[kat] ECC-384");
    Ecc384Kat::default().execute(env.ecc384, env.trng)?;

    cprintln!("[kat] ECDH");
    EcdhKat::default().execute(env.ecc384, env.trng)?;

    cprintln!("[kat] HMAC-384Kdf");
    Hmac384KdfKat::default().execute(env.hmac, env.trng)?;

    cprintln!("[kat] HMAC-512Kdf");
    Hmac512KdfKat::default().execute(env.hmac, env.trng)?;

    cprintln!("[kat] HKDF-384");
    Hkdf384Kat::default().execute(env.hmac, env.trng)?;

    cprintln!("[kat] HKDF-512");
    Hkdf512Kat::default().execute(env.hmac, env.trng)?;

    cprintln!("[kat] KDF-CMAC");
    CmacKdfKat::default().execute(env.aes)?;

    cprintln!("[kat] LMS");
    LmsKat::default().execute(env.sha256, env.lms)?;

    cprintln!("[kat] MLDSA87");
    Mldsa87Kat::default().execute(env.mldsa87, env.trng)?;

    cprintln!("[kat] AES-256-ECB");
    Aes256EcbKat::default().execute(env.aes)?;

    cprintln!("[kat] AES-256-CBC");
    Aes256CbcKat::default().execute(env.aes)?;

    cprintln!("[kat] AES-256-CMAC");
    Aes256CmacKat::default().execute(env.aes)?;

    cprintln!("[kat] AES-256-CTR");
    Aes256CtrKat::default().execute(env.aes)?;

    cprintln!("[kat] AES-256-GCM");
    Aes256GcmKat::default().execute(env.aes, env.trng)?;

    cprintln!("[kat] --");

    Ok(())
}
