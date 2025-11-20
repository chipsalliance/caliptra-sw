/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains the top level dispatch of various RT Flows.

--*/

pub mod dice;
mod fmc_alias_csr;
mod pcr;
mod rt_alias;
mod tci;

use crate::flow::rt_alias::RtAliasLayer;

use crate::fmc_env::FmcEnvFips;
use caliptra_cfi_lib::cfi_assert_ne;
use caliptra_drivers::{CaliptraResult, FwPersistentData, RomPersistentData};
use caliptra_error::CaliptraError;

/// Execute FMC Flows based on reset reason
///
/// # Arguments
///
/// * `env` - FMC Environment
pub fn run(env: &mut FmcEnvFips) -> CaliptraResult<()> {
    {
        use caliptra_cfi_lib::cfi_assert_eq;
        use caliptra_drivers::ResetReason;

        let reset_reason = env.soc_ifc.reset_reason();

        if reset_reason == ResetReason::ColdReset {
            cfi_assert_eq(env.soc_ifc.reset_reason(), ResetReason::ColdReset);

            let pdata = env.persistent_data.get_mut();
            pdata.rom.minor_version = RomPersistentData::MINOR_VERSION;
            pdata.fw.marker = FwPersistentData::MAGIC;
            pdata.fw.version = FwPersistentData::VERSION;

            // Generate the FMC Alias Certificate Signing Request (CSR)
            fmc_alias_csr::generate_csr(env)?;
        } else {
            cfi_assert_ne(env.soc_ifc.reset_reason(), ResetReason::ColdReset);

            let pdata = env.persistent_data.get();
            if pdata.rom.minor_version != RomPersistentData::MINOR_VERSION {
                return Err(CaliptraError::FMC_INVALID_ROM_PERSISTENT_DATA_VERSION);
            }
            if pdata.fw.marker != FwPersistentData::MAGIC {
                return Err(CaliptraError::FMC_INVALID_FW_PERSISTENT_DATA_MARKER);
            }
            if pdata.fw.version != FwPersistentData::VERSION {
                return Err(CaliptraError::FMC_INVALID_FW_PERSISTENT_DATA_VERSION);
            }
        }
    }

    RtAliasLayer::run(env)
}
