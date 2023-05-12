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
    let soc_ifc_regs = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc_regs.internal_iccm_lock().modify(|w| w.lock(true));

    unsafe {
        let iccm_start = 0x40000000_u32;
        let iccm_ptr = iccm_start as *mut u32;
        *iccm_ptr = 0xdeadbeef;
    }
    loop {}
}
