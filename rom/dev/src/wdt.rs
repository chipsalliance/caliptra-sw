/*++

Licensed under the Apache-2.0 license.

File Name:

    wdt.rs

Abstract:

    File contains execution routines for programming the Watchdog Timer.

Environment:

    ROM

--*/

use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::WdtTimeout;
use caliptra_drivers::SocIfc;

use crate::cprintln;

/// Start the Watchdog Timer
/// Note: WDT is configured only if the device is in non-debug mode (i.e debug_locked = 1)
///
/// # Arguments
///
/// * `soc_ifc` - SOC Interface
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn start_wdt(soc_ifc: &mut SocIfc) {
    if soc_ifc.debug_locked() {
        let mut wdt_timeout_cycles = soc_ifc.wdt1_timeout_cycle_count();
        if wdt_timeout_cycles == 0 {
            wdt_timeout_cycles = 1;
        }
        cprintln!(
            "[state] Starting the WD Timer {} cycles",
            wdt_timeout_cycles
        );
        caliptra_common::wdt::start_wdt(
            soc_ifc,
            WdtTimeout::from(core::num::NonZeroU64::new(wdt_timeout_cycles).unwrap()),
        );
    } else {
        cprintln!("[state] WD Timer not started. Device not locked for debugging");
    }
}
