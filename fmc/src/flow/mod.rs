/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

mod crypto;
pub mod dice;
mod fmc_alias_csr;
mod pcr;
mod rt_alias;
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
    {
        use caliptra_cfi_lib::{cfi_assert_eq, cfi_assert_ne};
        use caliptra_drivers::{PersistentData, ResetReason};
        use caliptra_error::CaliptraError;

        let reset_reason = env.soc_ifc.reset_reason();

        if reset_reason == ResetReason::ColdReset {
            cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::ColdReset);

            let pdata = env.persistent_data.get_mut();
            pdata.marker = PersistentData::MAGIC;
            pdata.version = PersistentData::VERSION;

            // Generate the FMC Alias Certificate Signing Request (CSR)
            fmc_alias_csr::generate_csr(env)?;
        } else {
            cfi_assert_ne(env.soc_ifc.reset_reason(), ResetReason::ColdReset);

            // Check persistent data is valid
            let pdata = env.persistent_data.get();
            if pdata.marker != PersistentData::MAGIC {
                return Err(CaliptraError::FMC_INVALID_FW_PERSISTENT_DATA_MARKER);
            }
            if pdata.version != PersistentData::VERSION {
                return Err(CaliptraError::FMC_INVALID_FW_PERSISTENT_DATA_VERSION);
            }
        }
    }

    RtAliasLayer::run(env)
}
