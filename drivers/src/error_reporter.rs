/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for Error Reporting via Soc Iface.

--*/
use caliptra_registers::soc_ifc::SocIfcReg;

/// Report non fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_non_fatal(val: u32) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_non_fatal().write(|_| val);
}

/// Report fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_fatal(val: u32) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_fatal().write(|_| val);
}
