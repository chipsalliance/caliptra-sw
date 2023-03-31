/*++

Licensed under the Apache-2.0 license.

File Name:

    exit_ctrl.rs

Abstract:

    File contains API for Caliptra Exit control

--*/

use caliptra_registers::soc_ifc;

const COLD_RESET: u8 = 0xf5;
const WARM_RESET: u8 = 0xf6;
const SINGLE_BIT_ERR_INJ: u8 = 0xfd;
const DBL_BIT_ERR_INJ: u8 = 0xfe;

/// Exit control
pub enum TbServices {}

impl TbServices {
    fn request_service(val: u32) {
        if cfg!(feature = "emu") {
            let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
            soc_ifc.cptra_generic_output_wires().at(0).write(|_| val);
        }
    }

    /// Single bit error injection
    ///
    /// # Returns
    ///
    /// This method does not return
    pub fn togle_single_bit_err_inject() {
        Self::request_service(SINGLE_BIT_ERR_INJ.into());
    }

    /// Double bit error injection
    ///
    /// # Returns
    ///
    /// This method does not return
    pub fn togle_double_bit_err_inject() {
        Self::request_service(DBL_BIT_ERR_INJ.into());
    }

    /// Request cold reset
    ///
    /// # Returns
    ///
    /// This method does not return
    pub fn cold_reset() {
        Self::request_service(COLD_RESET.into());
    }

    /// Request warm reset
    ///
    /// # Returns
    ///
    /// This method does not return
    pub fn warm_reset() {
        Self::request_service(WARM_RESET.into());
    }

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
        Self::request_service(if exit_code == 0 { 0xff } else { 0x01 });
        #[allow(clippy::empty_loop)]
        loop {}
    }
}
