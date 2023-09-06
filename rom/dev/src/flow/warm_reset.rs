/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::RomBootStatus::ColdResetComplete;
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
    pub fn run(env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
        cprintln!("[warm-reset] ++");

        // Check if previous Cold-Reset was successful.
        if cfi_launder(env.data_vault.rom_cold_boot_status()) != ColdResetComplete.into() {
            cprintln!("[warm-reset] Previous Cold-Reset was not successful.");
            return Err(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET);
        } else {
            cfi_assert!(env.data_vault.rom_cold_boot_status() == ColdResetComplete.into());
        }

        cprintln!("[warm-reset] --");

        Ok(None)
    }
}
