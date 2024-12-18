// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use ::core::arch::global_asm;

// Needed to bring in startup code
#[allow(unused)]
#[allow(clippy::single_component_path_imports)]
use caliptra_test_harness;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

global_asm!(
    r#"
main:
    lui t0, 0x50000
    li  t2, 0x100

writeloop:
// Write data to DCCM t2/4 times
    sw t0, 0(t0)
    addi t0, t0, 4
    addi t2, t2, -4
    bgtz t2, writeloop

    lui t0, 0x50000
    li  t2, 0x100
readloop:
// Read data from DCCM t2/4 times
    lw a0, 0(t0)
    addi t0, t0, 4
    addi t2, t2, -4
    bgtz t2, readloop
    ret
"#
);
