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
    lui t0, 0x40000
    lui t1, 0x40000
    li  t2, 0x100

    // Write (nop, nop) to ICCM t2/4 times
    li a0, 0x00010001
loop:
    sw a0, 0(t1)
    addi t1, t1, 4
    addi t2, t2, -4
    bgtz t2, loop

    // Write (ret) to ICCM
    li a0, 0x00008082
    sw a0, 0(t1)
    fence

    // Jump to ICCM
    jr t0
"#
);
