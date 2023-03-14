// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

extern crate fmc;

#[no_mangle]
pub extern "C" fn main() -> ! {
    loop {}
}

#[panic_handler]
#[inline(never)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
