// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_test_harness::test_suite;

fn test_preconditioned_aes256() {
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
}

test_suite! {
    test_preconditioned_aes256,
}
