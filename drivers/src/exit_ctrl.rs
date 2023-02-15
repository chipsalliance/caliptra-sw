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
        if cfg!(feature = "emu") {
            const STDOUT: *mut u32 = 0x3003_00C8 as *mut u32;
            unsafe {
                core::ptr::write_volatile(STDOUT, if exit_code == 0 { 0xff } else { 0x01 });
            }
        }

        loop {}
    }
}
