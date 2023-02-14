/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for Error Reporting via Soc Iface.

--*/
use caliptra_registers::soc_ifc;

/// Report non fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_non_fatal(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_fw_error_non_fatal().write(|_| val);
}

/// Report fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_fatal(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_fw_error_fatal().write(|_| val);
}

/// Report non fatal H/W error
///
/// # Arguments
///
/// * `val` - H/W error code.
pub fn report_hw_error_non_fatal(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_hw_error_non_fatal().write(|_| val);
}

/// Report fatal H/W error
///
/// # Arguments
///
/// * `val` - H/W error code.
pub fn report_hw_error_fatal(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_hw_error_fatal().write(|_| val);
}
