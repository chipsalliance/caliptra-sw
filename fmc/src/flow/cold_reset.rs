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

/// Warm Reset Flow
pub struct ColdResetFlow {}

impl ColdResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    #[inline(never)]
    pub fn run(_: &mut FmcEnv, _: &HandOff) -> CaliptraResult<()> {
        cprintln!("[cold-reset] ++");

        // TODO: Implement

        cprintln!("[cold-reset] --");

        Ok(())
    }
}
