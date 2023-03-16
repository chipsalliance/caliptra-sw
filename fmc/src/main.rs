// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]
#[macro_use]
extern crate caliptra_firmware;
use caliptra_firmware::printer;
#[no_mangle]
pub extern "C" fn main() -> ! {
    uformatln!("entering fmc");

    let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'S'.into());

    // 0xff means exit with success
    soc_ifc.cptra_generic_output_wires().at(0).write(|_| 0xff);

    loop {}
}
