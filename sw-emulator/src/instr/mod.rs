/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains implementation of RISCV Instructions

--*/

mod auipc;
mod branch;
mod jal;
mod jalr;
mod load;
mod lui;
mod op;
mod op_imm;
mod store;
mod system;
mod test_encoder;
mod test_macros;

use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::types::{RvInstr32, RvInstr32Opcode, RvSize};

/// Instruction
enum Instr {
    Compressed(u16),
    General(u32),
}

impl Cpu {
    /// Execute single instruction
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub(crate) fn exec_instr(
        &mut self,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        match self.fetch()? {
            Instr::Compressed(instr) => Err(RvException::illegal_instr(instr as u32)),
            Instr::General(instr) => self.exec_instr32(instr, instr_tracer),
        }
    }

    /// Fetch an instruction from current program counter
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::InstrAccessFault`
    ///                   or `RvExceptionCause::InstrAddrMisaligned`
    fn fetch(&self) -> Result<Instr, RvException> {
        let instr = self.read_instr(RvSize::HalfWord, self.read_pc())?;
        match instr & 0b11 {
            0 | 1 | 2 => Ok(Instr::Compressed(instr as u16)),
            _ => Ok(Instr::General(
                self.read_instr(RvSize::Word, self.read_pc())?,
            )),
        }
    }

    /// Execute single 32-bit instruction
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    fn exec_instr32(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        match RvInstr32(instr).opcode() {
            RvInstr32Opcode::Load => self.exec_load_instr(instr, instr_tracer)?,
            RvInstr32Opcode::OpImm => self.exec_op_imm_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Auipc => self.exec_auipc_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Store => self.exec_store_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Op => self.exec_op_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Lui => self.exec_lui_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Branch => self.exec_branch_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Jalr => self.exec_jalr_instr(instr, instr_tracer)?,
            RvInstr32Opcode::Jal => self.exec_jal_instr(instr, instr_tracer)?,
            RvInstr32Opcode::System => self.exec_system_instr(instr, instr_tracer)?,
            _ => Err(RvException::illegal_instr(instr))?,
        }

        self.inc_pc(4);

        Ok(())
    }
}
