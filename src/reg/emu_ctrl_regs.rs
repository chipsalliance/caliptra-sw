/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl_regs.rs

Abstract:

    File contains register definitions for Caliptra Emulator control

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::register_structs;
use tock_registers::registers::WriteOnly;

register_structs! {
    /// Emulator control registers
    pub(crate) EmuCtrlRegisters {
        /// Exit control
        (0x00 => pub(crate) exit: WriteOnly<u32>),

        (0x04 => @END),
    }
}

pub(crate) const EMU_CTRL_REGISTERS: StaticRef<EmuCtrlRegisters> =
    unsafe { StaticRef::new(0x2000_f000 as *const EmuCtrlRegisters) };
