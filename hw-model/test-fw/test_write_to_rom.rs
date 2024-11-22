// Licensed under the Apache-2.0 license

//! A very simple program to test the behavior of the CPU when trying to write to ROM.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::println;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    unsafe {
        let rom_address = 0x00_u32;
        let rom_address_ptr = rom_address as *mut u32;
        *rom_address_ptr = 0xdeadbeef;
    }
    #[allow(clippy::empty_loop)]
    loop {}
}
