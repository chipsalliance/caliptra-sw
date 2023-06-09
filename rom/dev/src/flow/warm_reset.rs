/*++

Licensed under the Apache-2.0 license.

File Name:

    warm_reset.rs

Abstract:

    File contains the implementation of warm reset flow.

--*/
use crate::{cprintln, rom_env::RomEnv};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::FirmwareHandoffTable;
use caliptra_error::CaliptraResult;

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
    pub fn run(_env: &mut RomEnv) -> CaliptraResult<Option<FirmwareHandoffTable>> {
        cprintln!("[warm-reset] ++");
        cprintln!("[warm-reset] --");

        Ok(None)
    }
}
