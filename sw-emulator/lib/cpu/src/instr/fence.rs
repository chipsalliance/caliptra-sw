/*++

Licensed under the Apache-2.0 license.

File Name:

    system.rs

Abstract:

    File contains implementation of system instructions.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32FenceFunct3, RvInstr32I, RvInstr32Opcode};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvException;

impl<TBus: Bus> Cpu<TBus> {
    /// Execute Fence Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_fence_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Fence);

        match instr.funct3().into() {
            RvInstr32FenceFunct3::Fence => {
                // Do nothing
                Ok(())
            }
            RvInstr32FenceFunct3::FenceI => {
                // Do nothing
                Ok(())
            }
            _ => Err(RvException::illegal_instr(instr.0)),
        }
    }
}
