/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_fail_repcnts_tests.rs

Abstract:
    https://opentitan.org/earlgrey_1.0.0/book/hw/ip/entropy_src/doc/theory_of_operation.html#repetition-count-symbol-test

    File contains test cases for CSRNG API when the physical entropy source
    produces repeated 4-bit symbols (nibbles).

    The Repetition Count Symbol (repcnts) health test is intentionally disabled
    in the driver. A repeating 4-bit symbol means every individual RNG wire is
    also constant, so the per-wire repetition count (repcnt) test still fails
    for these streams. We therefore expect CSRNG construction to fail with
    DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED.
--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_error::CaliptraError;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn test_boot_fail_repcnts_check() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg);

    if let Err(e) = csrng {
        assert_eq!(
            e,
            CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED,
            "error code should indicate the per-wire repetition count test failed (repcnts is disabled)"
        )
    } else {
        panic!("constant nibble stream should fail the repcnt test and prevent CSRNG from being constructed");
    }
}

test_suite! {
    test_boot_fail_repcnts_check,
}
