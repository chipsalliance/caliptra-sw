// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_drivers::{CaliptraError, CaliptraResult};

pub(crate) fn handle_impactless_update(drivers: &mut Drivers) -> CaliptraResult<()> {
    let cycles = drivers
        .soc_ifc
        .regs_mut()
        .internal_fw_update_reset_wait_cycles()
        .read()
        .into();
    for _ in 0..cycles {
        drivers
            .soc_ifc
            .regs_mut()
            .internal_fw_update_reset()
            .write(|w| w.core_rst(true));
    }

    Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN)
}
