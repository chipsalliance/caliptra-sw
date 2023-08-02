/*++

Licensed under the Apache-2.0 license.

File Name:

    kat.rs

Abstract:

    File contains execution routines for FIPS Known Answer Tests (KATs).

--*/

use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{report_boot_status, CaliptraResult};
use caliptra_kat::{Ecc384Kat, Hmac384Kat, LmsKat, Sha1Kat, Sha256Kat, Sha384AccKat, Sha384Kat};

use crate::{cprintln, rom_env::RomEnv};

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut RomEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");
    report_boot_status(KatStarted.into());

    cprintln!("[kat] sha1");
    Sha1Kat::default().execute(&mut env.sha1)?;

    cprintln!("[kat] SHA2-256");
    Sha256Kat::default().execute(&mut env.sha256)?;

    cprintln!("[kat] SHA2-384");
    Sha384Kat::default().execute(&mut env.sha384)?;

    cprintln!("[kat] SHA2-384-ACC");
    Sha384AccKat::default().execute(&mut env.sha384_acc)?;

    cprintln!("[kat] ECC-384");
    Ecc384Kat::default().execute(&mut env.ecc384, &mut env.trng)?;

    cprintln!("[kat] HMAC-384");
    Hmac384Kat::default().execute(&mut env.hmac384, &mut env.trng)?;

    cprintln!("[kat] LMS");
    LmsKat::default().execute(&mut env.sha256, &env.lms)?;

    report_boot_status(KatComplete.into());
    cprintln!("[kat] --");

    Ok(())
}
