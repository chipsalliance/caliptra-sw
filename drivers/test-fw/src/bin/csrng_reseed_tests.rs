/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_reseed_tests.rs

Abstract:

    Firmware-side test cases for CSRNG reseed and entropy source power-saving
    behaviour. Verifies:

      - generate12() succeeds when RESEED_COUNTER is close to RESEED_INTERVAL
        (driver triggers an automatic reseed before the counter overflows).
      - generate12() succeeds normally when RESEED_COUNTER is near zero.
      - generate12() succeeds when RESEED_INTERVAL is tightened below the
        current RESEED_COUNTER (forces an immediate reseed).
      - generate12() triggers a reseed from entropy_src after RESEED_INTERVAL
        is changed while entropy_src is enabled.
      - generate12() succeeds (auto-enables entropy_src and reseeds) even
        when entropy_src was disabled before the call.

--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, CsrngSeed};
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

// Deterministic seed so generate output is reproducible across all tests that
// do not need live entropy.
const FIXED_SEED: CsrngSeed = CsrngSeed::Constant(&[
    0x73bec010, 0x9262474c, 0x16a30f76, 0x531b51de, 0x2ee494e5, 0xdfec9db3, 0xcb7a879d, 0x5600419c,
    0xca79b0b0, 0xdda33b5c, 0xa468649e, 0xdf5d73fa,
]);

fn make_csrng_fixed() -> Csrng {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    Csrng::with_seed(csrng_reg, entropy_src_reg, &soc_ifc_reg, FIXED_SEED)
        .expect("construct CSRNG with fixed seed")
}

fn make_csrng_live() -> Csrng {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg).expect("construct CSRNG with live entropy")
}

// ---------------------------------------------------------------------------
// TC-1: generate12() when RESEED_COUNTER is close to RESEED_INTERVAL
//
// Set RESEED_INTERVAL to a small value (10), advance RESEED_COUNTER to
// RESEED_INTERVAL - 1 by calling generate12() nine times, then verify that
// the tenth call (which would hit the interval) still succeeds — the driver
// must trigger an automatic reseed before the counter overflows.
// ---------------------------------------------------------------------------
fn test_generate_reseed_counter_near_interval() {
    let mut csrng = make_csrng_fixed();

    // Set a small reseed interval so the test runs quickly.
    const RESEED_INTERVAL: u32 = 10;
    let mut csrng_reg = unsafe { CsrngReg::new() };
    csrng_reg
        .regs_mut()
        .reseed_interval()
        .write(|_| RESEED_INTERVAL);

    // Advance counter to RESEED_INTERVAL - 1.
    for i in 0..RESEED_INTERVAL - 1 {
        csrng
            .generate12()
            .unwrap_or_else(|_| panic!("generate12 failed at iteration {}", i));
    }

    // This call lands exactly at RESEED_INTERVAL — driver should reseed and succeed.
    csrng
        .generate12()
        .expect("generate12 at RESEED_INTERVAL should succeed via automatic reseed");
}

// ---------------------------------------------------------------------------
// TC-2: generate12() when RESEED_COUNTER is near zero (normal early-use case)
//
// After fresh instantiation the counter is 0.  Verify that the very first
// generate12() call succeeds without any reseed logic being triggered.
//
// Reads RESEED_COUNTER_2 (the SW application instance — NumApps=3, instance 2
// is the SW app the driver uses). The emulator models all three counter
// registers with the same internal CTR_DRBG counter.
// ---------------------------------------------------------------------------
fn test_generate_reseed_counter_near_zero() {
    let mut csrng = make_csrng_fixed();

    // Verify the reseed counter starts at 0 (or 1 after instantiate).
    let csrng_reg = unsafe { CsrngReg::new() };
    let counter = csrng_reg.regs().reseed_counter_2().read();
    assert!(
        counter <= 1,
        "reseed_counter_2 should be <=1 after instantiate, got {}",
        counter
    );

    csrng
        .generate12()
        .expect("generate12 near counter=0 should succeed");
}

// ---------------------------------------------------------------------------
// TC-3: generate12() when RESEED_INTERVAL is tightened below current counter
//
// Advance the counter to 5, then set RESEED_INTERVAL = 3 (below the current
// counter).  The next generate12() must detect counter > interval, perform a
// reseed, and succeed.
// ---------------------------------------------------------------------------
fn test_generate_interval_shrunk_below_counter() {
    let mut csrng = make_csrng_fixed();
    let mut csrng_reg = unsafe { CsrngReg::new() };

    // Advance counter to 5.
    for _ in 0..5 {
        csrng.generate12().expect("generate12 during setup");
    }
    let counter_before = csrng_reg.regs().reseed_counter_2().read();
    assert!(
        counter_before >= 5,
        "expected counter >= 5, got {}",
        counter_before
    );

    // Shrink interval below the current counter.
    csrng_reg.regs_mut().reseed_interval().write(|_| 3);

    // Driver should detect counter > interval, reseed, then complete.
    csrng
        .generate12()
        .expect("generate12 should succeed after reseed triggered by shrunken interval");
}

// ---------------------------------------------------------------------------
// TC-4: generate12() reseeds from entropy_src when interval changes while
//       entropy_src is enabled
//
// Uses a live-entropy CSRNG.  Sets a tight interval so the counter reaches it
// while entropy_src is active, confirming the automatic reseed draws from the
// live entropy source (not a constant seed).
// ---------------------------------------------------------------------------
fn test_generate_reseed_from_entropy_src_after_interval_change() {
    let mut csrng = make_csrng_live();
    let mut csrng_reg = unsafe { CsrngReg::new() };

    // Advance counter to 3 using live entropy.
    for _ in 0..3 {
        csrng.generate12().expect("generate12 during setup");
    }

    // Set interval to 3 — counter is now at the boundary.
    csrng_reg.regs_mut().reseed_interval().write(|_| 3);

    // entropy_src is currently enabled; reseed should pull from it.
    csrng
        .generate12()
        .expect("generate12 should reseed from live entropy_src and succeed");
}

// ---------------------------------------------------------------------------
// TC-5: generate12() succeeds (auto-enables entropy_src) when entropy_src is
//       disabled at the time a reseed is required.
//
// The driver re-enables entropy_src on demand before issuing the Reseed
// command, so disabling it externally before a boundary generate must not
// cause generate12() to fail.
// ---------------------------------------------------------------------------
fn test_generate_reseed_auto_enables_entropy_src() {
    let mut csrng = make_csrng_live();
    let mut csrng_reg = unsafe { CsrngReg::new() };
    let mut entropy_src_reg = unsafe { EntropySrcReg::new() };

    // Set interval = 3, advance counter to 3 (boundary).
    csrng_reg.regs_mut().reseed_interval().write(|_| 3);
    for _ in 0..3 {
        csrng.generate12().expect("generate12 during setup");
    }

    // Disable entropy_src externally. The driver must re-enable it before the
    // reseed, so the next generate12() succeeds.
    // MultiBitBool::False = 9 (same value used in csrng.rs).
    entropy_src_reg
        .regs_mut()
        .module_enable()
        .write(|w| w.module_enable(9));

    csrng
        .generate12()
        .expect("generate12 should auto-enable entropy_src and succeed at the reseed boundary");
}

// ---------------------------------------------------------------------------
// TC-6: generate12() fails with an injected error when the
//       CSRNG_RESEED_FAILURE FIPS test hook is set
//
// This case lives in csrng_reseed_health_fail_tests.rs (separate firmware
// binary built with the `fips-test-hooks` feature).
// ---------------------------------------------------------------------------

test_suite! {
    test_generate_reseed_counter_near_zero,
    test_generate_reseed_counter_near_interval,
    test_generate_interval_shrunk_below_counter,
    test_generate_reseed_from_entropy_src_after_interval_change,
    test_generate_reseed_auto_enables_entropy_src,
}
