/*++

Licensed under the Apache-2.0 license.

File Name:

    status_reporter.rs

Abstract:

    File contains API for reporting boot and flow status via Soc Iface.

--*/

use caliptra_registers::soc_ifc;

/// Report boot status
///
/// # Arguments
///
/// * `val` - Boot status code.
pub fn report_boot_status(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_boot_status().write(|_| val);
}

/// Report flow status
///
/// # Arguments
///
/// * `val` - Flow status code.
pub fn report_flow_status(val: u32) {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();

    let flow_status = soc_ifc.cptra_flow_status().read();
    soc_ifc
        .cptra_flow_status()
        .write(|_| flow_status.modify().status(val));
}
