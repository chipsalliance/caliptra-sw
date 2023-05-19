// Licensed under the Apache-2.0 license

//! A very simple ROM. Prints an 'F' character followed by a request to exit
//! with failure. Used for testing the toolchain and test infrastructure.

#![no_main]
#![no_std]

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut soc_ifc = unsafe { caliptra_registers::soc_ifc::SocIfcReg::new() };
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'F'.into());
    // 0xff means exit with failure
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0x01);
}
