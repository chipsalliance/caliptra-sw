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

#[derive(Default, Debug)]
pub struct FlowStatus {}

impl FlowStatus {
    /// Set IDEVID CSR ready
    ///
    /// # Arguments
    ///
    /// * None
    pub fn set_idevid_csr_ready(&mut self) {
        let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
        soc_ifc.cptra_flow_status().write(|w| w.status(0x0800_0000));
    }

    /// Set ready for firmware
    ///
    /// # Arguments
    ///
    /// * None
    pub fn set_ready_for_firmware(&mut self) {
        let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
        soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
    }
}
