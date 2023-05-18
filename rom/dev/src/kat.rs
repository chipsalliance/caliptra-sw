/*++

Licensed under the Apache-2.0 license.

File Name:

    kat.rs

Abstract:

    File contains execution routines for FIPS Known Answer Tests (KATs).

--*/

use caliptra_drivers::CaliptraResult;
use caliptra_kat::{Ecc384Kat, Hmac384Kat, LmsKat, Sha1Kat, Sha256Kat, Sha384AccKat, Sha384Kat};

use crate::{cprintln, rom_env::RomEnv};

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut RomEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");

    cprintln!("[kat] Executing SHA1 Engine KAT");
    Sha1Kat::default().execute(&mut env.sha1)?;

    cprintln!("[kat] Executing SHA2-256 Engine KAT");
    Sha256Kat::default().execute(&mut env.sha256)?;

    cprintln!("[kat] Executing SHA2-384 Engine KAT");
    Sha384Kat::default().execute(&mut env.sha384)?;

    cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
    Sha384AccKat::default().execute(&mut env.sha384_acc)?;

    cprintln!("[kat] Executing ECC-384 Engine KAT");
    Ecc384Kat::default().execute(&mut env.ecc384)?;

    cprintln!("[kat] Executing HMAC-384 Engine KAT");
    Hmac384Kat::default().execute(&mut env.hmac384)?;

    cprintln!("[kat] Executing LMS Engine KAT");
    LmsKat::default().execute(&mut env.sha256, &env.lms)?;

    cprintln!("[kat] --");

    Ok(())
}
