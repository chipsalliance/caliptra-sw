/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the implementation of the val ROM reset flows

--*/

#[allow(dead_code)]
#[path = "flow/cold_reset/fw_processor.rs"]
mod fw_processor;

use crate::fht;
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::{report_boot_status, CaliptraResult, ResetReason};
use caliptra_error::CaliptraError;
use fw_processor::FirmwareProcessor;

/// Execute ROM Flows based on reset reason
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
    let reset_reason = env.soc_ifc.reset_reason();
    match reset_reason {
        // Cold Reset Flow
        ResetReason::ColdReset => {
            cprintln!("[val-rom-cold-reset] ++");
            report_boot_status(ColdResetStarted.into());

            // SKIP Execute IDEVID layer
            // SKIP Execute LDEVID layer

            // Download and validate firmware.
            _ = FirmwareProcessor::process(env)?;

            // SKIP Execute FMCALIAS layer

            cprintln!("[val-rom-cold-reset] --");
            report_boot_status(ColdResetComplete.into());

            Ok(Some(fht::make_fht(env)))
        }

        // TODO: Warm Reset Flow
        ResetReason::WarmReset => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),

        // TODO: Update Reset Flow
        ResetReason::UpdateReset => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),

        // Unknown/Spurious Reset Flow
        ResetReason::Unknown => Err(CaliptraError::ROM_UNKNOWN_RESET_FLOW),
    }
}
