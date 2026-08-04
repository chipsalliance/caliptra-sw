/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_reseed_health_fail_tests.rs

Abstract:

    Firmware for TC-6: injects a reseed failure via the CSRNG_RESEED_FAILURE
    FIPS test hook, for platforms where the real TRNG cannot produce bad
    entropy (e.g. FPGA in itrng mode).

    The host arms the hook by writing CSRNG_RESEED_FAILURE to bits 23:16 of
    cptra_dbg_manuf_service_reg before boot. The driver's reseed() calls
    FipsTestHook::error_if_hook_set(), returning FIPS_HOOKS_INJECTED_ERROR on
    the next reseed.

    This firmware:
      1. Initialises CSRNG with live entropy (startup passes — the hook is
         only checked on the reseed path).
      2. Sets RESEED_INTERVAL = 1 so the next generate triggers a reseed.
      3. Calls generate12() and expects the reseed to fail.

    Built with the `fips-test-hooks` cargo feature.

--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_error::CaliptraError;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn test_reseed_fails_on_health_check_failure() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    // Startup health checks pass — the hook is only checked on the reseed path.
    let mut csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg)
        .expect("CSRNG should pass startup health testing");

    // Set a tight interval so the next generate triggers a reseed.
    let mut csrng_reg2 = unsafe { CsrngReg::new() };
    csrng_reg2.regs_mut().reseed_interval().write(|_| 1);

    // First generate12() does not trigger Phase 2 (counter < interval);
    // it succeeds and advances the counter to the interval.
    csrng
        .generate12()
        .expect("first generate12 should succeed (counter < interval)");

    // The next generate12() enters Phase 2 and calls reseed(); the FIPS hook
    // fires there. send_command() maps the failure to DRIVER_CSRNG_RESEED,
    // so either error is acceptable.
    let result = csrng.generate12();
    match result {
        Err(CaliptraError::FIPS_HOOKS_INJECTED_ERROR) | Err(CaliptraError::DRIVER_CSRNG_RESEED) => {
            // Expected: the injected hook caused the reseed to fail.
        }
        Err(e) => {
            panic!("unexpected error {:?}", e);
        }
        Ok(_) => {
            panic!("expected reseed failure from FIPS hook, but generate12 succeeded");
        }
    }
}

test_suite! {
    test_reseed_fails_on_health_check_failure,
}
