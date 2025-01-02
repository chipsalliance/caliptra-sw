/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

mod crypto;
pub mod dice;
#[cfg(feature = "fmc-alias-csr")]
mod fmc_alias_csr;
mod pcr;
mod rt_alias;
mod tci;
mod x509;

use crate::flow::rt_alias::RtAliasLayer;

use crate::fmc_env::FmcEnv;
use caliptra_drivers::CaliptraResult;

/// Execute FMC Flows based on reset resason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnv) -> CaliptraResult<()> {
    #[cfg(feature = "fmc-alias-csr")]
    {
        use caliptra_cfi_lib::cfi_assert_eq;
        use caliptra_drivers::ResetReason;

        let reset_reason = env.soc_ifc.reset_reason();

        if reset_reason == ResetReason::ColdReset {
            cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::ColdReset);
            // Generate the FMC Alias Certificate Signing Request (CSR)
            fmc_alias_csr::generate_csr(env)?;
        }
    }

    RtAliasLayer::run(env)
}
