/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various ROM Flows.

--*/

mod cold_reset;
#[cfg(feature = "fake-rom")]
mod fake;
mod update_reset;
mod warm_reset;

use crate::cprintln;
use crate::{handle_fatal_error, rom_env::RomEnv};
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_cfi_lib::cfi_assert_eq;
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::{CaliptraResult, ResetReason};
use caliptra_error::CaliptraError;

/// Execute ROM Flows based on reset reason
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
    let reset_reason = env.soc_ifc.reset_reason();

    if cfg!(not(feature = "fake-rom")) {
        match reset_reason {
            // Cold Reset Flow
            ResetReason::ColdReset => {
                cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::ColdReset);
                cold_reset::ColdResetFlow::run(env)
            }

            // Warm Reset Flow
            ResetReason::WarmReset => {
                cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::WarmReset);
                warm_reset::WarmResetFlow::run(env)
            }

            // Update Reset Flow
            ResetReason::UpdateReset => {
                cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::UpdateReset);
                update_reset::UpdateResetFlow::run(env)
            }

            // Unknown/Spurious Reset Flow
            ResetReason::Unknown => {
                cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::Unknown);
                Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW)
            }
        }
    } else {
        let _result: CaliptraResult<Option<FirmwareHandoffTable>> =
            Err(CaliptraError::ROM_GLOBAL_PANIC);

        if env.soc_ifc.lifecycle() == caliptra_drivers::Lifecycle::Production {
            cprintln!("Fake ROM in Production lifecycle prohibited");
            handle_fatal_error(CaliptraError::ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION.into());
        }

        #[cfg(feature = "fake-rom")]
        let _result = fake::FakeRomFlow::run(env);

        _result
    }
}
