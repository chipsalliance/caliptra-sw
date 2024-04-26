/*++

Licensed under the Apache-2.0 license.

File Name:

    update.rs

Abstract:

    File contains FirmwareLoad mailbox command.

--*/

use crate::Drivers;
use caliptra_cfi_derive_git::cfi_mod_fn;
use caliptra_drivers::{CaliptraError, CaliptraResult};

#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub(crate) fn handle_impactless_update(drivers: &mut Drivers) -> CaliptraResult<()> {
    let cycles = drivers.soc_ifc.internal_fw_update_reset_wait_cycles();
    for _ in 0..cycles {
        drivers.soc_ifc.assert_fw_update_reset();
    }

    Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN)
}
