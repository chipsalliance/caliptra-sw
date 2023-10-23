/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_tests.rs

Abstract:

    File contains test cases for CSRNG API

--*/
#![no_std]
#![no_main]

use caliptra_drivers::{Csrng, CsrngSeed};

use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

// From:
// https://github.com/lowRISC/opentitan/blob/ff70cfe194f5a2bb08c1a87a949b5c45746a5d99/sw/device/tests/csrng_smoketest.c#L27
fn test_ctr_drbg_ctr0_smoke() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    const SEED: CsrngSeed = CsrngSeed::Constant(&[
        0x73bec010, 0x9262474c, 0x16a30f76, 0x531b51de, 0x2ee494e5, 0xdfec9db3, 0xcb7a879d,
        0x5600419c, 0xca79b0b0, 0xdda33b5c, 0xa468649e, 0xdf5d73fa,
    ]);

    const EXPECTED_OUTPUT: [u32; 12] = [
        0x725eda90, 0xc79b4a14, 0xe43b74ac, 0x9d9a938b, 0xc395a610, 0x4c5a1483, 0xa45f15e8,
        0x2708cbef, 0x89eb63a9, 0x70cdc6bc, 0x710daba1, 0xed39808c,
    ];

    let mut csrng =
        Csrng::with_seed(csrng_reg, entropy_src_reg, &soc_ifc_reg, SEED).expect("construct CSRNG");

    // The original OpenTitan test tosses the first call to generate.
    let _ = csrng
        .generate12()
        .expect("first call to generate should work");

    assert_eq!(
        csrng
            .generate12()
            .expect("second call to generate should work"),
        EXPECTED_OUTPUT
    );
}

// Note: this test is sensitive to the TRNG bits that are fed into the emulation model.
fn test_entropy_src_seed() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    const EXPECTED_OUTPUT: [u32; 4] = [0xca3d3c2f, 0x552adb53, 0xa9749c5d, 0xdabbe4c3];
    let mut csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg).expect("construct CSRSNG");

    assert_eq!(
        csrng
            .generate12()
            .expect("first call to generate should work")[..EXPECTED_OUTPUT.len()],
        EXPECTED_OUTPUT
    );
}

fn test_zero_health_fails() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    let csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg).expect("construct CSRNG");
    let counts = csrng.health_fail_counts();
    assert_eq!(counts.total, 0, "Expected zero total health check fails");
    assert_eq!(
        u32::from(counts.specific),
        0,
        "Expected zero specific health check fails"
    );
}

test_suite! {
    test_ctr_drbg_ctr0_smoke,
    test_entropy_src_seed,
    test_zero_health_fails,

    // TODO(rkr35): Induce failing health checks and assert we can observe them.
    // TODO(rkr35): Test Reseed and Update commands.
}
