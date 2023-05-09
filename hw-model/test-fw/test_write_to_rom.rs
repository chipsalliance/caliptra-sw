// Licensed under the Apache-2.0 license

//! A very simple program that sends mailbox transactions.

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
        // Access unmapped address. This should trigger a non-fatal error
        // and the ROM should signal a non-fatal error to the SoC.
        let rom_address = 0x00_u32;
        let rom_address_ptr = rom_address as *mut u32;
        *rom_address_ptr = 0xdeadbeef;
    }
    loop {}
}
