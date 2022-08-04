/*++

Licensed under the Apache-2.0 license.

File Name:

    lui.rs

Abstract:

    File contains implementation of Load Upper Immediate (`lui`) instruction.

--*/

use crate::bus::Bus;
use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{RvData, RvInstr, RvInstr32Opcode, RvInstr32U};

impl<TBus: Bus> Cpu<TBus> {
    /// Execute `lui` Instruction
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_lui_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32U(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Lui);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::UType(instr));

        // Calculate the value
        let val = instr.imm().wrapping_shl(12) as RvData;

        // Save the contents to register
        self.write_xreg(instr.rd(), val)
    }
}

#[cfg(test)]
mod tests {
    use crate::{isa_test, test_lui, text};

    // ---------------------------------------------------------------------------------------------
    // Tests For Load Upper Immediate (`lui`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lui.S
    // ----------------------------------------------------------------------------------------------------------------

    test_lui!(test_lui_2, 0x00000000, 0x00000, 0);
    test_lui!(test_lui_3, 0xFFFFF800, 0xFFFFF, 1);
    test_lui!(test_lui_4, 0x000007FF, 0x7FFFF, 20);
    test_lui!(test_lui_5, 0xFFFFF800, 0x80000, 20);
}
