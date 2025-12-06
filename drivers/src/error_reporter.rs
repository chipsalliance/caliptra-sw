/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for Error Reporting via Soc Iface.

--*/
use crate::memory_layout::BOOT_STATUS_ORG;
use crate::PersistentData;
use caliptra_registers::soc_ifc::SocIfcReg;

/// Report non fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_non_fatal(val: u32) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_non_fatal().write(|_| val);

    update_boot_status(&mut soc_ifc);
}

/// Get non fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn get_fw_error_non_fatal() -> u32 {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_non_fatal().read()
}

/// Clear non fatal F/W error
///
/// /// # Arguments
///
/// * `persistent_data` - Persistent data struct so we can track cleared errors.
pub fn clear_fw_error_non_fatal(persistent_data: &mut PersistentData) {
    match get_fw_error_non_fatal() {
        0 => {}
        val => {
            // If there is a non-zero error, save it in persistent data before clearing
            persistent_data.rom.cleared_non_fatal_fw_error = val;
            report_fw_error_non_fatal(0);
        }
    }
}

/// Report fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
pub fn report_fw_error_fatal(val: u32) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_fatal().write(|_| val);

    update_boot_status(&mut soc_ifc);
}

fn update_boot_status(soc_ifc: &mut SocIfcReg) {
    // Retrieve the boot status from DCCM and save it in the boot status register.
    unsafe {
        let ptr = BOOT_STATUS_ORG as *mut u32;
        soc_ifc.regs_mut().cptra_boot_status().write(|_| *ptr);
    };
}
