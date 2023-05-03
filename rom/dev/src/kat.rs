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
pub fn execute_kat(env: &RomEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");

    cprintln!("[kat] Executing SHA1 Engine KAT");
    env.sha1().map(|s| Sha1Kat::default().execute(s))?;

    cprintln!("[kat] Executing SHA2-256 Engine KAT");
    env.sha256().map(|s| Sha256Kat::default().execute(s))?;

    cprintln!("[kat] Executing SHA2-384 Engine KAT");
    env.sha384().map(|s| Sha384Kat::default().execute(s))?;

    cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
    env.sha384_acc()
        .map(|s| Sha384AccKat::default().execute(s))?;

    cprintln!("[kat] Executing ECC-384 Engine KAT");
    env.ecc384().map(|e| Ecc384Kat::default().execute(e))?;

    cprintln!("[kat] Executing HMAC-384 Engine KAT");
    env.hmac384().map(|h| Hmac384Kat::default().execute(h))?;

    cprintln!("[kat] Executing LMS Engine KAT");
    env.lms().map(|l| LmsKat::default().execute(l))?;

    cprintln!("[kat] --");

    Ok(())
}
