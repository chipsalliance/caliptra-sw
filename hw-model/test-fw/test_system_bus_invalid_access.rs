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
        let addr = 0xFFFF_0000_u32;
        let ptr = addr as *mut u32;
        *ptr = 0xdeadbeef;
    }
    loop {}
}
