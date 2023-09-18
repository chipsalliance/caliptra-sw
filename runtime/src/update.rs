// Licensed under the Apache-2.0 license

use crate::Drivers;
use caliptra_drivers::{CaliptraError, CaliptraResult};

pub(crate) fn handle_impactless_update(drivers: &mut Drivers) -> CaliptraResult<()> {
    let cycles = drivers.soc_ifc.internal_fw_update_reset_wait_cycles();
    for _ in 0..cycles {
        drivers.soc_ifc.assert_fw_update_reset();
    }

    Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN)
}
