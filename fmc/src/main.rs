// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]
use panic_never as _;

core::arch::global_asm!(include_str!("start.S"));
#[macro_use]
mod printer;
use ufmt;

use core::ptr;

#[no_mangle]
pub extern "C" fn main() -> ! {
    uformatln!("FMC is running");
    caliptra_lib::ExitCtrl::exit(0);
    #[allow(clippy::empty_loop)]
    loop {}
}

//#[panic_handler]
//#[inline(never)]
//fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
//loop {}
//}
