// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use ::core::arch::global_asm;

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

global_asm!(
    r#"
main:
    C.UNIMP
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret
"#
);
