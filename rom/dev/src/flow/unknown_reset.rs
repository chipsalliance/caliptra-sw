/*++

Licensed under the Apache-2.0 license.

File Name:

    unknown_reset.rs

Abstract:

    File contains the implementation of unknown/spurious reset flow.

--*/
use crate::{cprintln, fht, rom_env::RomEnv};
use caliptra_common::FirmwareHandoffTable;
use caliptra_drivers::CaliptraResult;

/// Unknown Reset
#[derive(Default)]
pub struct UnknownResetFlow {}

impl UnknownResetFlow {
    /// Execute unknown/spurious reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    pub fn run(env: &RomEnv) -> CaliptraResult<FirmwareHandoffTable> {
        cprintln!("[unknown-reset] ++");

        // TODO: Implement

        cprintln!("[unknown-reset] --");

        Ok(fht::make_fht(env))
    }
}
