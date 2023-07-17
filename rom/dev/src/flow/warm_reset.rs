/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::CaliptraResult;

/// Warm Reset Flow
pub struct WarmResetFlow {}

impl WarmResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(_env: &mut RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[warm-reset] ++");

        cprintln!("[warm-reset] --");

        // Caller does not expect an FHT in the case of a warm reset.
        Ok(FirmwareHandoffTable::default())
    }
}
