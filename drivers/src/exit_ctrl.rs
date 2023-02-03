/*++

Licensed under the Apache-2.0 license.

File Name:

    exit_ctrl.rs

Abstract:

    File contains API for Caliptra Exit control

--*/

use cfg_if::cfg_if;

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
    pub fn exit(_exit_code: u32) -> ! {
        cfg_if! {
            if #[cfg(feature = "emu")] {
                const STDOUT: *mut u32 = 0x3003_00A8 as *mut u32;
                unsafe {
                    core::ptr::write_volatile(STDOUT, 0xFF_u32);
                }
            }
        }

        loop {}
    }
}
