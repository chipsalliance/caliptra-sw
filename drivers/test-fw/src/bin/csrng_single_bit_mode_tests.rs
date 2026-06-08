/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_single_bit_mode_tests.rs

Abstract:

    Tests entropy_src single-bit mode configuration from SS_STRAP_GENERIC[2].

--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

const MULTI_BIT_BOOL_FALSE: u32 = 9;
const MULTI_BIT_BOOL_TRUE: u32 = 6;
const EXPECTED_RNG_BIT_SEL: u32 = 2;

fn test_single_bit_mode_configured() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };

    let _csrng =
        Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg).expect("CSRNG initialization failed");

    let entropy_src = unsafe { EntropySrcReg::new() };
    let conf = entropy_src.regs().conf().read();

    assert_eq!(
        conf.rng_bit_enable(),
        MULTI_BIT_BOOL_TRUE,
        "RNG_BIT_ENABLE should be set from SS_STRAP_GENERIC[2][16]"
    );
    assert_eq!(
        conf.rng_bit_sel(),
        EXPECTED_RNG_BIT_SEL,
        "RNG_BIT_SEL should be set from SS_STRAP_GENERIC[2][18:17]"
    );
    assert_eq!(
        conf.threshold_scope(),
        MULTI_BIT_BOOL_FALSE,
        "THRESHOLD_SCOPE should be false in entropy_src single-bit mode"
    );
}

test_suite! {
    test_single_bit_mode_configured,
}
