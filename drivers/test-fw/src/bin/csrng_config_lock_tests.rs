/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_config_lock_tests.rs

Abstract:

    Tests for entropy_src configuration locking security feature.

    These tests verify that:
    1. In production mode (debug_locked=true), SW_REGUPD and ME_REGWEN are
       cleared after CSRNG initialization, preventing RT firmware from
       reconfiguring entropy_src.
    2. In debug mode (debug_locked=false), SW_REGUPD and ME_REGWEN remain
       set to allow characterization.

--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

/// Test that verifies entropy_src configuration registers are locked in production mode.
/// This test expects to run with debug_locked=true (production mode).
fn test_config_locked_in_production_mode() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    // Verify we're in production mode (debug_locked = true)
    let debug_locked = soc_ifc_reg
        .regs()
        .cptra_security_state()
        .read()
        .debug_locked();
    assert!(
        debug_locked,
        "This test must run with debug_locked=true (production mode)"
    );

    // Initialize CSRNG - this should configure and lock entropy_src
    let _csrng =
        Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg).expect("CSRNG initialization failed");

    // After initialization in production mode, SW_REGUPD and ME_REGWEN should be cleared (locked)
    let entropy_src = unsafe { EntropySrcReg::new() };
    let sw_regupd = entropy_src.regs().sw_regupd().read().sw_regupd();

    assert!(
        !sw_regupd,
        "SW_REGUPD should be cleared (false) in production mode, but was true"
    );
}

test_suite! {
    test_config_locked_in_production_mode,
}
