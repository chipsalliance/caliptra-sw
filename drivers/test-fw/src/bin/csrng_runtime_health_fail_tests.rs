/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_runtime_health_fail_tests.rs

Abstract:
    https://opentitan.org/book/hw/ip/entropy_src/index.html#description

    This test verifies that CSRNG properly detects health check failures that occur
    during runtime (after boot-time health checks pass). This is critical for detecting
    low-entropy scenarios where the entropy source initially appears healthy but
    degrades during operation.

    The test expects:
    - Boot-time health check to PASS (CSRNG::new succeeds)
    - Runtime health check to FAIL (generate12 fails)
--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, PersistentDataAccessor};
use caliptra_error::CaliptraError;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn test_runtime_health_check_failure() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let persistent_data = unsafe { PersistentDataAccessor::new() };

    // CSRNG initialization should succeed with good boot-time entropy
    let mut csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg, persistent_data)
        .expect("CSRNG should pass boot-time health test");

    // First generate should start seeing bad entropy
    // The emulator will be configured to provide good entropy for boot,
    // then bad entropy for runtime operations
    let result = csrng.generate12();

    match result {
        Err(CaliptraError::DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED) => {
            // Expected: repetition count test failed during runtime
        }
        Err(CaliptraError::DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED) => {
            // Also acceptable: adaptive proportion test failed during runtime
        }
        Err(e) => {
            panic!("Expected health check failure error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Expected generate12 to fail due to runtime health check failure");
        }
    }
}

test_suite! {
    test_runtime_health_check_failure,
}
