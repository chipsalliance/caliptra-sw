/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_fail_repcnt_tests.rs

Abstract:
    https://opentitan.org/book/hw/ip/entropy_src/doc/theory_of_operation.html#repetition-count-test

    File contains test cases for CSRNG API when the physical entropy source
    has a stuck bit on at least one of the four external RNG wires.

    We expect the Repetition Count health check to fail for these tests.
--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_error::CaliptraError;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg};
use caliptra_test_harness::test_suite;

fn test_boot_fail_repcnt_check() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let csrng = Csrng::new(csrng_reg, entropy_src_reg);

    if let Err(e) = csrng {
        assert_eq!(
            e,
            CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED,
            "error code should indicate the repetition count test failed"
        )
    } else {
        panic!("failing repetition count test should prevent CSRNG from being constructed");
    }
}

test_suite! {
    test_boot_fail_repcnt_check,
}
