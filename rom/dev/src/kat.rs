/*++

Licensed under the Apache-2.0 license.

File Name:

    kat.rs

Abstract:

    File contains execution routines for FIPS Known Answer Tests (KATs).

--*/

use caliptra_drivers::{report_boot_status, CaliptraResult};

use crate::rom_env::RomEnv;
use caliptra_common::RomBootStatus::{KatComplete, KatStarted};

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut RomEnv) -> CaliptraResult<()> {
    let mut kats_env = caliptra_kat::KatsEnv {
        // SHA1 Engine
        sha1: &mut env.sha1,

        // sha256
        sha256: &mut env.sha256,

        // SHA2-384 Engine
        sha384: &mut env.sha384,

        // SHA2-384 Accelerator
        sha384_acc: &mut env.sha384_acc,

        // Hmac384 Engine
        hmac384: &mut env.hmac384,

        /// Cryptographically Secure Random Number Generator
        trng: &mut env.trng,

        // LMS Engine
        lms: &mut env.lms,

        /// Ecc384 Engine
        ecc384: &mut env.ecc384,
    };

    report_boot_status(KatStarted.into());
    caliptra_kat::execute_kat(&mut kats_env)?;
    report_boot_status(KatComplete.into());
    Ok(())
}
