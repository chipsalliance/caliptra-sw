/*++

Licensed under the Apache-2.0 license.

File Name:

    wdt.rs

Abstract:

    File contains execution routines for programming the Watchdog Timer.


--*/

use caliptra_drivers::SocIfc;

use crate::cprintln;

pub struct WdtTimeout(pub core::num::NonZeroU64);

impl Default for WdtTimeout {
    fn default() -> WdtTimeout {
        WdtTimeout::new_const(WDT1_MIN_TIMEOUT_IN_CYCLES)
    }
}

impl WdtTimeout {
    pub const ROM_WDT1_TIMEOUT_IN_CYCLES: WdtTimeout =
        WdtTimeout::new_const(10 * EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES);
    pub const fn new_const(timeout_cycles: u64) -> Self {
        match core::num::NonZeroU64::new(timeout_cycles) {
            Some(val) => Self(val),
            None => panic!("WdtTimeout cannot be 0"),
        }
    }
}

impl From<core::num::NonZeroU64> for WdtTimeout {
    fn from(val: core::num::NonZeroU64) -> Self {
        WdtTimeout(val)
    }
}
impl From<WdtTimeout> for core::num::NonZeroU64 {
    fn from(val: WdtTimeout) -> Self {
        val.0
    }
}
impl From<WdtTimeout> for u64 {
    fn from(val: WdtTimeout) -> Self {
        core::num::NonZeroU64::from(val).get()
    }
}

const EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES: u64 = 20_000_000; // 20 million cycles
const WDT2_TIMEOUT_CYCLES: u64 = 1; // Fire immediately after WDT1 expiry

const WDT1_MIN_TIMEOUT_IN_CYCLES: u64 = EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES;

/// Start the Watchdog Timer
///
/// # Arguments
///
/// * `soc_ifc` - SOC Interface
///
///
pub fn start_wdt(soc_ifc: &mut SocIfc, wdt1_timeout_cycles: WdtTimeout) {
    // Set WDT1 period.
    soc_ifc.set_wdt1_timeout(wdt1_timeout_cycles.into());

    // Set WDT2 period.
    soc_ifc.set_wdt2_timeout(WDT2_TIMEOUT_CYCLES);

    // Enable WDT1 only. WDT2 is automatically scheduled (since it is disabled) on WDT1 expiry.
    soc_ifc.configure_wdt1(true);

    restart_wdt(soc_ifc);
}

/// Restart the Watchdog Timer
///
/// # Arguments
///
/// * `env` - ROM Environment
///
pub fn restart_wdt(soc_ifc: &mut SocIfc) {
    cprintln!("[state] Restarting the Watchdog Timer");

    // Only restart WDT1. WDT2 is automatically scheduled (since it is disabled) on WDT1 expiry.
    soc_ifc.reset_wdt1();
}

/// Stop the Watchdog Timer
///
/// # Arguments
///
/// * `soc_ifc` - SOC Interface
///
pub fn stop_wdt(soc_ifc: &mut SocIfc) {
    soc_ifc.configure_wdt1(false);
}
