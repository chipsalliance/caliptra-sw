/*++

Licensed under the Apache-2.0 license.

File Name:

    update_reset.rs

Abstract:

    File contains the implementation of unknown/spurious reset flow.

--*/
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_drivers::CaliptraResult;

#[derive(Default)]
pub struct UpdateResetFlow {}

impl UpdateResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    #[inline(never)]
    pub fn run(_: &FmcEnv, _: &mut HandOff) -> CaliptraResult<()> {
        cprintln!("[update-reset] ++");

        // TODO: Implement

        cprintln!("[update-reset] --");

        Ok(())
    }
}
