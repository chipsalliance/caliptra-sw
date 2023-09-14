// Licensed under the Apache-2.0 license

//! A very simple ROM. Prints a serious of strings using the UART driver.

#![no_std]
#![no_main]

use caliptra_drivers::{ExitCtrl, Uart};
// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn main() {
    Uart::new().write("aa");
    Uart::new().write("aaa");
    Uart::new().write("ahello");
    ExitCtrl::exit(0);
}
