/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Caliptra Known Answer Tests.

--*/

#![no_std]

mod ecc384_kat;
mod hmac384kdf_kat;
mod kats_env;
mod lms_kat;
mod sha1_kat;
mod sha256_kat;
mod sha384_kat;
mod sha384acc_kat;

pub use caliptra_drivers::{CaliptraError, CaliptraResult};
pub use ecc384_kat::Ecc384Kat;
pub use hmac384kdf_kat::Hmac384KdfKat;
pub use kats_env::KatsEnv;
pub use lms_kat::LmsKat;
pub use sha1_kat::Sha1Kat;
pub use sha256_kat::Sha256Kat;
pub use sha384_kat::Sha384Kat;
pub use sha384acc_kat::Sha384AccKat;

use caliptra_drivers::cprintln;

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut KatsEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");

    cprintln!("[kat] sha1");
    Sha1Kat::default().execute(env.sha1)?;

    cprintln!("[kat] SHA2-256");
    Sha256Kat::default().execute(env.sha256)?;

    cprintln!("[kat] SHA2-384");
    Sha384Kat::default().execute(env.sha384)?;

    cprintln!("[kat] SHA2-384-ACC");
    Sha384AccKat::default().execute(env.sha384_acc, env.sha_acc_lock_state)?;

    cprintln!("[kat] ECC-384");
    Ecc384Kat::default().execute(env.ecc384, env.trng)?;

    cprintln!("[kat] HMAC-384");
    Hmac384KdfKat::default().execute(env.hmac384, env.trng)?;

    cprintln!("[kat] LMS");
    LmsKat::default().execute(env.sha256, env.lms)?;

    cprintln!("[kat] --");

    Ok(())
}
