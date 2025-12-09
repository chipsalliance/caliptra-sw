/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert_eq, cfi_assert_ne, cfi_launder};
use caliptra_common::{handle_fatal_error, RomBootStatus::*};
use caliptra_drivers::RomPersistentData;
use caliptra_error::{CaliptraError, CaliptraResult};

/// Warm Reset Flow
pub struct WarmResetFlow {}

impl WarmResetFlow {
    /// Execute update reset flow
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    #[inline(never)]
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn run(env: &mut RomEnv) -> CaliptraResult<()> {
        cprintln!("[warm-reset] ++");

        // Check persistent data is valid
        let pdata = env.persistent_data.get();
        if pdata.rom.marker != RomPersistentData::MAGIC {
            handle_fatal_error(CaliptraError::ROM_INVALID_ROM_PERSISTENT_DATA_MARKER.into())
        }
        // Only check the major version because the minor version may have been modified by FMC
        if pdata.rom.major_version != RomPersistentData::MAJOR_VERSION {
            handle_fatal_error(CaliptraError::ROM_INVALID_ROM_PERSISTENT_DATA_VERSION.into())
        }

        let data_vault = &env.persistent_data.get().rom.data_vault;

        // Check if previous Cold-Reset was successful.
        if cfi_launder(data_vault.rom_cold_boot_status()) != ColdResetComplete.into() {
            return Err(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET);
        } else {
            cfi_assert_eq(data_vault.rom_cold_boot_status(), ColdResetComplete.into());
        }

        // Check if previous Update-Reset, if any,  was successful.
        if cfi_launder(data_vault.rom_update_reset_status()) == UpdateResetStarted.into() {
            return Err(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET);
        } else {
            cfi_assert_ne(
                data_vault.rom_update_reset_status(),
                UpdateResetStarted.into(),
            );
        }

        cprintln!("[warm-reset] --");

        Ok(())
    }
}
