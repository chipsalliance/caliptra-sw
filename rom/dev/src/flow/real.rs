use crate::flow::cold_reset;
use crate::flow::update_reset;
use crate::flow::warm_reset;
use crate::RomEnv;
use caliptra_cfi_lib::cfi_assert_eq;
use caliptra_drivers::{CaliptraResult, ResetReason};
use caliptra_error::CaliptraError;

pub struct RealRomFlow {}

impl RealRomFlow {
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        let reset_reason = env.soc_ifc.reset_reason();

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
    }
}
