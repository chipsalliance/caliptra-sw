// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]
core::arch::global_asm!(include_str!("start.S"));

#[cfg(feature = "emu")]
#[macro_use]
mod printer;
#[cfg(feature = "emu")]
use core::ptr;
#[cfg(feature = "emu")]
use ufmt;

#[no_mangle]
pub extern "C" fn main() -> ! {
    #[cfg(feature = "emu")]
    uformatln!("FMC is running");
    const STDOUT: *mut u32 = 0x3003_00C8 as *mut u32;
    unsafe {
        core::ptr::write_volatile(STDOUT, 0xff);
    }
    loop {}
}

#[panic_handler]
#[inline(never)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
