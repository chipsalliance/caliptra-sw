/*++

Licensed under the Apache-2.0 license.

File Name:

    unknown_reset.rs

Abstract:

    File contains the implementation of unknown/spurious reset flow.

--*/
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_drivers::CaliptraResult;

/// Unknown Reset
#[derive(Default)]
pub struct UnknownResetFlow {}

impl UnknownResetFlow {
    /// Execute unknown/spurious reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    #[inline(never)]
    pub fn run(_: &FmcEnv, _: &HandOff) -> CaliptraResult<()> {
        cprintln!("[unknown-reset] ++");

        // TODO: Implement

        cprintln!("[unknown-reset] --");

        Ok(())
    }
}
