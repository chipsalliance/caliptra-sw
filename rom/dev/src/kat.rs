/*++

Licensed under the Apache-2.0 license.

File Name:

    kat.rs

Abstract:

    File contains execution routines for FIPS Known Answer Tests (KATs).

--*/

use caliptra_drivers::{report_boot_status, CaliptraResult};

use crate::KatsEnv;
use caliptra_common::RomBootStatus::{KatComplete, KatStarted};

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(kats_env: &mut KatsEnv) -> CaliptraResult<()> {
    report_boot_status(KatStarted.into());
    caliptra_kat::execute_kat(kats_env)?;
    report_boot_status(KatComplete.into());
    Ok(())
}
