// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use caliptra_registers::{self, mbox::MboxCsr, soc_ifc::SocIfcReg};

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut mbox = unsafe { MboxCsr::new() };
    let mut soc_ifc = unsafe { SocIfcReg::new() };

    let ptr = soc_ifc.regs_mut().cptra_rsvd_reg().at(0).read() as *const u32;
    let size = soc_ifc.regs_mut().cptra_rsvd_reg().at(1).read() as usize;

    // Lock the mailbox so we can access the mailbox SRAM if necessary
    mbox.regs_mut().lock().read();

    let mut i = 0;
    while i < size / 4 {
        unsafe { ptr.add(i).read_volatile() };
        i += 1;
    }

    // Exit success
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0xff);
    loop {}
}
