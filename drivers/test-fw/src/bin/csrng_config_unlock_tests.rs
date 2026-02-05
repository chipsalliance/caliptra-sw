/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_config_unlock_tests.rs

Abstract:

    Tests for entropy_src configuration in debug mode.

    This test verifies that in debug mode (debug_locked=false), SW_REGUPD and
    ME_REGWEN remain set after CSRNG initialization, allowing characterization
    and debugging of the entropy source.

--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, PersistentDataAccessor};
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

/// Test that verifies entropy_src configuration registers remain unlocked in debug mode.
/// This test expects to run with debug_locked=false (debug mode).
fn test_config_unlocked_in_debug_mode() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let persistent_data = unsafe { PersistentDataAccessor::new() };

    // Verify we're in debug mode (debug_locked = false)
    let debug_locked = soc_ifc_reg
        .regs()
        .cptra_security_state()
        .read()
        .debug_locked();
    assert!(
        !debug_locked,
        "This test must run with debug_locked=false (debug mode)"
    );

    // Initialize CSRNG - this should configure but NOT lock entropy_src in debug mode
    let _csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg, persistent_data)
        .expect("CSRNG initialization failed");

    // After initialization in debug mode, SW_REGUPD and ME_REGWEN should remain set (unlocked)
    let entropy_src = unsafe { EntropySrcReg::new() };
    let sw_regupd = entropy_src.regs().sw_regupd().read().sw_regupd();
    let me_regwen = entropy_src.regs().me_regwen().read().me_regwen();

    assert!(
        sw_regupd,
        "SW_REGUPD should remain set (true) in debug mode, but was false"
    );
    assert!(
        me_regwen,
        "ME_REGWEN should remain set (true) in debug mode, but was false"
    );
}

test_suite! {
    test_config_unlocked_in_debug_mode,
}
