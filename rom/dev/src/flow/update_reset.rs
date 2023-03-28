/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of update reset flow.

--*/

use crate::{cprintln, fht, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::CaliptraResult;

#[derive(Default)]
pub struct UpdateResetFlow {}

impl UpdateResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    pub fn run(env: &RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[update-reset] ++");

        // TODO: Implement

        cprintln!("[update-reset] --");

        Ok(fht::make_fht(env))
    }
}
