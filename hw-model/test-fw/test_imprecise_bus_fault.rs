// Licensed under the Apache-2.0 license

//! A very simple program to test the behavior of the CPU when trying to write to ROM.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::println;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    unsafe {
        let address = 0xf002_00f0_u32;
        let ptr = address as *mut u32;
        *ptr = 0x3002_00f0;
    }
    loop {}
}
