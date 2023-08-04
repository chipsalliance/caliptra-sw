// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use core::num::NonZeroUsize;

use caliptra_drivers::Csrng;
use caliptra_registers::{csrng::CsrngReg, entropy_src::EntropySrcReg};
use caliptra_test_harness::test_suite;

fn test_assume_initialized() {
    let csrng_reg = unsafe { CsrngReg::new() };
    let entropy_src_reg = unsafe { EntropySrcReg::new() };

    let mut csrng0 = Csrng::new(csrng_reg, entropy_src_reg).expect("construct CSRNG");

    let one = NonZeroUsize::new(1).unwrap();

    assert_eq!(csrng0.generate(one).unwrap().next().unwrap(), 0x15eb2a44);

    {
        let mut csrng1 =
            unsafe { Csrng::assume_initialized(CsrngReg::new(), EntropySrcReg::new()) };

        assert_eq!(csrng1.generate(one).unwrap().next().unwrap(), 0xb5848d3a);
    }

    assert_eq!(csrng0.generate(one).unwrap().next().unwrap(), 0x22a79509);
}

test_suite! {
    test_assume_initialized,
}
