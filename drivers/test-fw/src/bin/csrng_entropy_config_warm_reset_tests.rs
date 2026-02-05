/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_entropy_config_warm_reset_tests.rs

Abstract:
    This test verifies that entropy source configuration is preserved across warm resets,
    even if someone maliciously modifies the CPTRA_ITRNG config registers during runtime.

    The ROM stores entropy configuration in persistent data during cold boot. On warm reset,
    the stored values are used instead of re-reading from registers. This prevents runtime
    malicious modification from persisting.

    Test scenario:
    - Cold reset: CSRNG initializes successfully with default thresholds
      Then we write bad values to CPTRA_ITRNG registers (that would fail health checks)
      Signal for warm reset
    - Warm reset: CSRNG should initialize successfully using stored values
      (ignoring the bad register values)

    NOTE: This test requires the entropy configuration persistence feature from PR #3256.
--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, PersistentDataAccessor, ResetReason, SocIfc};
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

/// Magic boot status to signal test harness we're ready for warm reset
const WARM_RESET_READY_BOOT_STATUS: u32 = 0xCAFE_1234;

fn test_entropy_config_warm_reset() {
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let mut soc_ifc = SocIfc::new(soc_ifc_reg);

    match soc_ifc.reset_reason() {
        ResetReason::ColdReset => cold_reset_flow(),
        ResetReason::WarmReset => warm_reset_flow(),
        _ => panic!("Unexpected reset reason"),
    }
}

fn cold_reset_flow() -> ! {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let persistent_data = unsafe { PersistentDataAccessor::new() };

    // First, initialize CSRNG normally - this should succeed and store config in persistent data
    let csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg, persistent_data);
    assert!(
        csrng.is_ok(),
        "CSRNG should initialize successfully on cold reset"
    );

    // Drop the CSRNG to release the registers
    drop(csrng);

    // Now, write BAD values to the CPTRA_ITRNG config registers
    // These values would cause health checks to fail if used:
    // - adaptp_lo = 0xffff (higher than any reasonable hi threshold)
    // - adaptp_hi = 0x0001 (lower than lo threshold - impossible to pass)
    // - repcnt = 0x0001 (threshold of 1 means any repeated bit fails)
    let mut soc_ifc_reg = unsafe { SocIfcReg::new() };

    // Write bad adaptive proportion thresholds
    // high_threshold in low 16 bits, low_threshold in high 16 bits
    // Setting lo=0xFFFF, hi=0x0001 is impossible to satisfy
    soc_ifc_reg
        .regs_mut()
        .cptra_i_trng_entropy_config_0()
        .write(|w| {
            w.high_threshold(0x0001) // Impossibly low hi threshold
                .low_threshold(0xFFFF) // Impossibly high lo threshold
        });

    // Write bad repetition count threshold
    // repetition_count in low 16 bits
    // Setting threshold to 1 means any repeated bit fails
    soc_ifc_reg
        .regs_mut()
        .cptra_i_trng_entropy_config_1()
        .write(|w| {
            w.repetition_count(0x0001) // Threshold of 1 = immediate failure
        });

    // Signal test harness that we're ready for warm reset
    loop {
        soc_ifc_reg
            .regs_mut()
            .cptra_boot_status()
            .write(|_| WARM_RESET_READY_BOOT_STATUS);
    }
}

fn warm_reset_flow() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let persistent_data = unsafe { PersistentDataAccessor::new() };

    // On warm reset, CSRNG should use the configuration stored in persistent data
    // from cold boot, NOT the bad values we wrote to the registers.
    // Therefore, this initialization should succeed.
    let csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg, persistent_data);

    match csrng {
        Ok(mut c) => {
            // Also verify we can generate successfully
            let result = c.generate12();
            assert!(
                result.is_ok(),
                "CSRNG generate should work with original config"
            );
        }
        Err(e) => {
            panic!("CSRNG should initialize successfully on warm reset using stored config, but got error: {:?}", e);
        }
    }
}

test_suite! {
    test_entropy_config_warm_reset,
}
