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
use caliptra_common::RomBootStatus::*;
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

        let data_vault = &env.persistent_data.get().data_vault;

        // Check if previous Cold-Reset was successful.
        if cfi_launder(data_vault.rom_cold_boot_status()) != ColdResetComplete.into() {
            cprintln!("[warm-reset] Prev Cold-Reset failed");
            return Err(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET);
        } else {
            cfi_assert_eq(data_vault.rom_cold_boot_status(), ColdResetComplete.into());
        }

        // Check if previous Update-Reset, if any,  was successful.
        if cfi_launder(data_vault.rom_update_reset_status()) == UpdateResetStarted.into() {
            cprintln!("[warm-reset] Prev Update Reset failed");
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
