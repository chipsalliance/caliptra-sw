/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various ROM Flows.

--*/

mod cold_reset;
mod update_reset;
#[cfg(feature = "val-rom")]
mod val;
mod warm_reset;

use crate::cprintln;
use crate::{handle_fatal_error, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::{CaliptraResult, ResetReason};
use caliptra_error::CaliptraError;

/// Execute ROM Flows based on reset reason
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
    let reset_reason = env.soc_ifc.reset_reason();

    if cfg!(not(feature = "val-rom")) {
        match reset_reason {
            // Cold Reset Flow
            ResetReason::ColdReset => cold_reset::ColdResetFlow::run(env),

            // Warm Reset Flow
            ResetReason::WarmReset => warm_reset::WarmResetFlow::run(env),

            // Update Reset Flow
            ResetReason::UpdateReset => update_reset::UpdateResetFlow::run(env),

            // Unknown/Spurious Reset Flow
            ResetReason::Unknown => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),
        }
    } else {
        let _result: CaliptraResult<Option<FirmwareHandoffTable>> =
            Err(CaliptraError::ROM_GLOBAL_PANIC);

        if env.soc_ifc.lifecycle() == caliptra_drivers::Lifecycle::Production {
            cprintln!("Validation ROM in Production lifecycle prohibited");
            handle_fatal_error(CaliptraError::ROM_GLOBAL_VAL_ROM_IN_PRODUCTION.into());
        }

        #[cfg(feature = "val-rom")]
        let _result = val::ValRomFlow::run(env);

        _result
    }
}
