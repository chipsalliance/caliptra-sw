/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_fail_repcnt_tests.rs

Abstract:
    https://opentitan.org/earlgrey_1.0.0/book/hw/ip/entropy_src/doc/theory_of_operation.html#repetition-count-test

    File contains test cases for CSRNG API when the physical entropy source
    has a stuck bit on at least one of the four external RNG wires.

    We expect the Repetition Count health check to fail for these tests.
--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, EntropyRegs, PersistentDataAccessor};
use caliptra_error::CaliptraError;
use caliptra_registers::{csrng::CsrngReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn test_boot_fail_repcnt_check() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_regs = unsafe { EntropyRegs::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let persistent_data = unsafe { PersistentDataAccessor::new() };
    let csrng = Csrng::new(csrng_reg, entropy_regs, &soc_ifc_reg, persistent_data);

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
