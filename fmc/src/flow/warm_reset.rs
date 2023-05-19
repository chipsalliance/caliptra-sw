/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::fmc_env::FmcEnv;
use crate::HandOff;
use caliptra_common::cprintln;
use caliptra_drivers::CaliptraResult;

/// Unknown Reset
#[derive(Default)]
pub struct WarmResetFlow {}

impl WarmResetFlow {
    /// Execute unknown/spurious reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    #[inline(never)]
    pub fn run(_: &mut FmcEnv, _: &mut HandOff) -> CaliptraResult<()> {
        cprintln!("[warm-reset] ++");

        // TODO: Implement

        cprintln!("[warm-reset] --");

        Ok(())
    }
}
