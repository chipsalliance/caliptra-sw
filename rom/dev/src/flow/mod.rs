/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various ROM Flows.

--*/

mod cold_reset;
mod unknown_reset;
mod update_reset;
mod warm_reset;

use crate::rom_env::RomEnv;
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::{CaliptraResult, ResetReason};

pub use cold_reset::KEY_ID_CDI;
pub use cold_reset::KEY_ID_FMC_PRIV_KEY;

/// Execute ROM Flows based on reset resason
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn run(env: &RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
    let reset_reason = env.reset().map(|r| r.reset_reason());
    match reset_reason {
        // Cold Reset Flow
        ResetReason::ColdReset => cold_reset::ColdResetFlow::run(env),

        // Warm Reset Flow
        ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env),

        // Update Reset Flow
        ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env),

        // Unknown/Spurious Reset Flow
        ResetReason::Unknown => unknown_reset::UnknownResetFlow::run(env),
    }
}
