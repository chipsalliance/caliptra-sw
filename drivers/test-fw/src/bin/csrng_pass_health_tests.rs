/*++

Licensed under the Apache-2.0 license.

File Name:

    csrng_pass_health_tests.rs

Abstract:
    https://opentitan.org/book/hw/ip/entropy_src/index.html#description

    The test cases in this file should pass entropy health tests.
--*/
#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg, soc_ifc::SocIfcReg};
use caliptra_test_harness::test_suite;

fn test_boot_and_generate_pass() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };
    let soc_ifc_reg = unsafe { SocIfcReg::new() };
    let mut csrng = Csrng::new(csrng_reg, entropy_src_reg, &soc_ifc_reg)
        .expect("CSRNG should pass boot-time health test");
    let _ = csrng
        .generate12()
        .expect("CSRNG should pass continuous health tests (first generate)");
    let _ = csrng
        .generate12()
        .expect("CSRNG should pass continuous health tests (second generate)");
}

test_suite! {
    test_boot_and_generate_pass,
}
