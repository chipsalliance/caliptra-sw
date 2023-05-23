/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_tests.rs

Abstract:

    File contains test cases for CSRNG API

--*/
#![no_std]
#![no_main]

use core::iter::zip;
use core::num::NonZeroUsize;

use caliptra_drivers::{Csrng, CsrngSeed};

use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg};
use caliptra_test_harness::test_suite;

// From:
// https://github.com/lowRISC/opentitan/blob/ff70cfe194f5a2bb08c1a87a949b5c45746a5d99/sw/device/tests/csrng_smoketest.c#L27
fn test_ctr_drbg_ctr0_smoke() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };

    const SEED: CsrngSeed = CsrngSeed::Constant(&[
        0x73bec010, 0x9262474c, 0x16a30f76, 0x531b51de, 0x2ee494e5, 0xdfec9db3, 0xcb7a879d,
        0x5600419c, 0xca79b0b0, 0xdda33b5c, 0xa468649e, 0xdf5d73fa,
    ]);

    const EXPECTED_OUTPUT: [u32; 16] = [
        0xe48bb8cb, 0x1012c84c, 0x5af8a7f1, 0xd1c07cd9, 0xdf82ab22, 0x771c619b, 0xd40fccb1,
        0x87189e99, 0x510494b3, 0x64f7ac0c, 0x2581f391, 0x80b1dc2f, 0x793e01c5, 0x87b107ae,
        0xdb17514c, 0xa43c41b7,
    ];

    let mut csrng = Csrng::with_seed(csrng_reg, entropy_src_reg, SEED).expect("construct CSRNG");
    let mut output = [0; EXPECTED_OUTPUT.len()];
    let num_words = NonZeroUsize::new(output.len()).expect("non-zero num_words");

    // The original OpenTitan test tosses the first call to generate.
    let _ = csrng.generate(num_words).expect("generate1");

    for (dst, src) in zip(&mut output, csrng.generate(num_words).expect("generate2")) {
        *dst = src;
    }

    assert_eq!(output, EXPECTED_OUTPUT);
}

// Requires the hardware model to have been seeded with the TRNG nibbles found here:
// https://github.com/chipsalliance/caliptra-rtl/blob/fa91d66f30223899403f4e65a6f697a6f9100fd1/src/csrng/tb/csrng_tb.sv#L461
fn test_entropy_src_seed() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };

    const EXPECTED_OUTPUT: [u32; 4] = [0x15eb2a44, 0x310851dd, 0xba1365ab, 0x4c7322f4];

    let mut csrng = Csrng::new(csrng_reg, entropy_src_reg).expect("construct CSRSNG");
    let mut output = [0; EXPECTED_OUTPUT.len()];
    let num_words = NonZeroUsize::new(output.len()).expect("non-zero num_words");

    for (dst, src) in zip(&mut output, csrng.generate(num_words).expect("generate")) {
        *dst = src;
    }

    assert_eq!(output, EXPECTED_OUTPUT);
}

fn test_zero_health_fails() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };

    let csrng = Csrng::new(csrng_reg, entropy_src_reg).expect("construct CSRNG");
    let counts = csrng.health_counts();
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
