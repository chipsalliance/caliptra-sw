// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::Csrng;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg};
use caliptra_test_harness::test_suite;

fn test_assume_initialized() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };

    let mut csrng0 = Csrng::new(csrng_reg, entropy_src_reg).expect("construct CSRNG");

    assert_eq!(csrng0.generate12().unwrap()[0], 0xca3d3c2f);

    {
        let mut csrng1 =
            unsafe { Csrng::assume_initialized(CsrngReg::new(), EntropySrcReg::new()) };

        assert_eq!(csrng1.generate12().unwrap()[0], 0x7d63f096);
    }

    assert_eq!(csrng0.generate12().unwrap()[0], 0x248474c6);
}

test_suite! {
    test_assume_initialized,
}
