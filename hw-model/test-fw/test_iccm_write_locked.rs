// Licensed under the Apache-2.0 license

//! A very simple program that sends mailbox transactions.

#![no_main]
#![no_std]

// Needed to bring in startup code
use caliptra_registers::soc_ifc::SocIfcReg;
#[allow(unused)]
use caliptra_test_harness::println;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc
        .regs_mut()
        .internal_iccm_lock()
        .modify(|w| w.lock(true));

    unsafe {
        let iccm_start = 0x40000000_u32;
        let iccm_ptr = iccm_start as *mut u32;
        *iccm_ptr = 0xdeadbeef;
    }
    #[allow(clippy::empty_loop)]
    loop {}
}
