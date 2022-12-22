/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl.rs

Abstract:

    File contains API for Caliptra Emulator control

--*/

use crate::reg::emu_ctrl_regs::EMU_CTRL_REGISTERS;
use tock_registers::interfaces::Writeable;

/// Emulator control
pub enum EmuCtrl {}

impl EmuCtrl {
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
        EMU_CTRL_REGISTERS.exit.set(exit_code);
        loop {}
    }
}
