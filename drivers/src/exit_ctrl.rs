/*++

Licensed under the Apache-2.0 license.

File Name:

    exit_ctrl.rs

Abstract:

    File contains API for Caliptra Exit control

--*/

/// Exit control
pub enum ExitCtrl {}

impl ExitCtrl {
    /// Exit the emulator
    ///
    /// # Arguments
    ///
    /// * `exit_code`: Code to exit the emulator process with
    ///
    /// # Returns
    ///
    /// This method does not return
    pub fn exit(exit_code: u32) -> ! {
        let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| if exit_code == 0 { 0xff } else { 0x01 });
        #[allow(clippy::empty_loop)]
        loop {}
    }
}
