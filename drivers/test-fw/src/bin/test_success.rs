// Licensed under the Apache-2.0 license

//! A very simple ROM. Prints an 'S' character followed by a request to exit
//! with success. Used for testing the toolchain and test infrastructure.

#![no_main]
#![no_std]

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[allow(clippy::empty_loop)]
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut soc_ifc = unsafe { caliptra_registers::soc_ifc::SocIfcReg::new() };
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'S'.into());
    // 0xff means exit with success
    soc_ifc
        .regs_mut()
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| 0xff);
    #[allow(clippy::empty_loop)]
    loop {}
}
