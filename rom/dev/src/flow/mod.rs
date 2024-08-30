/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various ROM Flows.

--*/

mod cold_reset;
mod update_reset;
mod warm_reset;

#[cfg(feature = "fake-rom")]
mod fake;
#[cfg(feature = "fake-rom")]
type ActiveFlow = crate::flow::fake::FakeRomFlow;

#[cfg(not(feature = "fake-rom"))]
mod real;
#[cfg(not(feature = "fake-rom"))]
type ActiveFlow = crate::flow::real::RealRomFlow;

use crate::rom_env::RomEnv;
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_drivers::CaliptraResult;

/// Execute ROM Flows based on real or fake ROM
///
/// # Arguments
///
/// * `env` - ROM Environment
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
    ActiveFlow::run(env)
}
