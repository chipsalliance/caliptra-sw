/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Caliptra Known Answer Tests.

--*/

#![no_std]

mod ecc384_kat;
mod ecdh_kat;
mod hkdf_kat;
mod hmac_kdf_kat;
mod kats_env;
mod lms_kat;
mod mldsa87_kat;
mod sha256_kat;
mod sha2_512_384acc_kat;
mod sha384_kat;
mod sha3_kat;
mod sha512_kat;

pub use caliptra_drivers::{CaliptraError, CaliptraResult};
pub use ecc384_kat::Ecc384Kat;
pub use ecdh_kat::EcdhKat;
pub use hkdf_kat::{Hkdf384Kat, Hkdf512Kat};
pub use hmac_kdf_kat::{Hmac384KdfKat, Hmac512KdfKat};
pub use kats_env::KatsEnv;
pub use lms_kat::LmsKat;
pub use mldsa87_kat::Mldsa87Kat;
pub use sha256_kat::Sha256Kat;
pub use sha2_512_384acc_kat::Sha2_512_384AccKat;
pub use sha384_kat::Sha384Kat;
pub use sha3_kat::Shake256Kat;
pub use sha512_kat::Sha512Kat;

use caliptra_drivers::{cprintln, Sha1};

/// Drivers that have been initialized after KAT execution
pub struct InitializedDrivers {
    pub sha1: Sha1,
}

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut KatsEnv) -> CaliptraResult<InitializedDrivers> {
    cprintln!("[kat] ++");

    cprintln!("[kat] sha1");
    let sha1 = Sha1::new()?;

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

    // Run AES KATs - ROM only has access to GCM and CMAC-KDF via AesGcm,
    // while non-ROM builds have access to all AES modes via Aes.
    #[cfg(feature = "rom")]
    {
        cprintln!("[kat] AES-GCM + KDF-CMAC");
        env.aes_gcm.run_kats(env.trng)?;
    }

    #[cfg(not(feature = "rom"))]
    {
        cprintln!("[kat] KDF-CMAC");
        caliptra_drivers::kats::execute_cmackdf_kat(env.aes)?;
        cprintln!("[kat] AES-ECB");
        caliptra_drivers::kats::execute_ecb_kat(env.aes)?;
        cprintln!("[kat] AES-CBC");
        caliptra_drivers::kats::execute_cbc_kat(env.aes)?;
        cprintln!("[kat] AES-CTR");
        caliptra_drivers::kats::execute_ctr_kat(env.aes)?;
        cprintln!("[kat] AES-CMAC");
        caliptra_drivers::kats::execute_cmac_kat(env.aes)?;
        cprintln!("[kat] AES-GCM");
        caliptra_drivers::kats::execute_gcm_kat(env.aes, env.trng)?;
    }

    cprintln!("[kat] LMS");
    LmsKat::default().execute(env.sha256, env.lms)?;

    cprintln!("[kat] MLDSA87");
    Mldsa87Kat::default().execute(env.mldsa87, env.trng)?;

    cprintln!("[kat] --");

    Ok(InitializedDrivers { sha1 })
}
