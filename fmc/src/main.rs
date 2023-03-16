// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]
extern crate caliptra_rt;

#[no_mangle]
pub extern "C" fn main() -> ! {
    let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc
        .cptra_generic_output_wires()
        .at(0)
        .write(|_| b'S'.into());

    loop {}
}
