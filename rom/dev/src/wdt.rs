/*++

Licensed under the Apache-2.0 license.

File Name:

    wdt.rs

Abstract:

    File contains execution routines for programming the Watchdog Timer.

Environment:

    ROM

--*/

use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_drivers::SocIfc;
use core::cmp::max;

use crate::cprintln;

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles
const WDT1_TIMEOUT_SECS: u32 = 5;
const WDT2_TIMEOUT_CYCLES: u64 = 1; // Fire immediately after WDT1 expiry

pub(crate) struct WatchdogTimer {}

impl WatchdogTimer {
    /// Start the Watchdog Timer
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn start_wdt(soc_ifc: &mut SocIfc) {
        cprintln!("[state] Starting the Watchdog Timer");

        let wdt1_timeout_cycles: u64 = match soc_ifc.get_cycle_count(WDT1_TIMEOUT_SECS) {
            Ok(cycle_count) => max(EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES * 10, cycle_count),
            Err(_) => EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES * 10,
        };

        // Set WDT1 period.
        soc_ifc.set_wdt1_timeout(wdt1_timeout_cycles);

        // Set WDT2 period.
        soc_ifc.set_wdt2_timeout(WDT2_TIMEOUT_CYCLES);

        // Enable WDT1 only. WDT2 is automatically scheduled (since it is disabled) on WDT1 expiry.
        soc_ifc.configure_wdt1(true);
    }

    /// Restart the Watchdog Timer
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    ///
    // [TODO] Enable this once WDT ownership tp FMC is resolved.
    // pub fn restart_wdt(soc_ifc: &mut SocIfc) {
    //     cprintln!("[state] Restarting the Watchdog Timer");

    //     // Only restart WDT1. WDT2 is automatically scheduled (since it is disabled) on WDT1 expiry.
    //     soc_ifc.reset_wdt1();
    // }

    /// Stop the Watchdog Timer
    ///
    /// # Arguments
    ///
    /// * `soc_ifc` - SOC Interface
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn stop_wdt(soc_ifc: &mut SocIfc) {
        cprintln!("[state] Stopping the Watchdog Timer");
        soc_ifc.configure_wdt1(false);
    }
}
