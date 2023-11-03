/*++

Licensed under the Apache-2.0 license.

File Name:

    mod.rs

Abstract:

    File contains implementation of RISCV Instructions

References:
    https://riscv.org/wp-content/uploads/2019/06/riscv-spec.pdf

--*/

mod auipc;
mod branch;
mod compression;
mod fence;
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

use crate::cpu::{Cpu, InstrTracer, StepAction};
use crate::types::{RvInstr, RvInstr32, RvInstr32Opcode};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvException, RvSize};

/// Instruction
pub enum Instr {
    Compressed(u16),
    General(u32),
}

impl<TBus: Bus> Cpu<TBus> {
    /// Skips the current instruction
    pub fn skip_instr(&mut self) -> Result<(), RvException> {
        let instr = self.fetch()?;

        match instr {
            Instr::Compressed(_) => {
                self.set_next_pc(self.read_pc().wrapping_add(2));
            }
            Instr::General(_) => {
                self.set_next_pc(self.read_pc().wrapping_add(4));
            }
        }

        self.write_pc(self.next_pc());

        Ok(())
    }

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
        instr_tracer: Option<&mut InstrTracer>,
    ) -> Result<StepAction, RvException> {
        // Set In Execution Mode and remove Hit
        self.is_execute_instr = true;
        self.watch_ptr_cfg.hit = None;

        let instr = self.fetch()?;

        // Code coverage here.
        self.code_coverage.log_execution(self.read_pc(), &instr);

        match instr {
            Instr::Compressed(instr) => {
                self.set_next_pc(self.read_pc().wrapping_add(2));

                self.exec_instr16(instr, instr_tracer)?;
            }
            Instr::General(instr) => {
                self.set_next_pc(self.read_pc().wrapping_add(4));

                self.exec_instr32(instr, instr_tracer)?;
            }
        }

        self.write_pc(self.next_pc());

        self.is_execute_instr = false;

        match self.get_watchptr_hit() {
            Some(_hit) => Ok(StepAction::Break),
            None => Ok(StepAction::Continue),
        }
    }

    /// Fetch an instruction from current program counter
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::InstrAccessFault`
    ///                   or `RvExceptionCause::InstrAddrMisaligned`
    fn fetch(&mut self) -> Result<Instr, RvException> {
        let instr = self.read_instr(RvSize::HalfWord, self.read_pc())?;
        match instr & 0b11 {
            0 | 1 | 2 => Ok(Instr::Compressed(instr as u16)),
            _ => Ok(Instr::General(
                self.read_instr(RvSize::Word, self.read_pc())?,
            )),
        }
    }

    /// Execute a single 16-bit instruction `instr`, tracing instructions to
    /// `instr_tracer` if it exists.
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    fn exec_instr16(
        &mut self,
        instr: u16,
        instr_tracer: Option<&mut InstrTracer>,
    ) -> Result<(), RvException> {
        if let Some(instr_tracer) = instr_tracer {
            instr_tracer(self.read_pc(), RvInstr::Instr16(instr))
        }
        self.exec_instr32(compression::decompress_instr(instr)?, None)
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
        instr_tracer: Option<&mut InstrTracer>,
    ) -> Result<(), RvException> {
        if let Some(instr_tracer) = instr_tracer {
            instr_tracer(self.read_pc(), RvInstr::Instr32(instr))
        }

        match RvInstr32(instr).opcode() {
            RvInstr32Opcode::Load => self.exec_load_instr(instr)?,
            RvInstr32Opcode::OpImm => self.exec_op_imm_instr(instr)?,
            RvInstr32Opcode::Auipc => self.exec_auipc_instr(instr)?,
            RvInstr32Opcode::Store => self.exec_store_instr(instr)?,
            RvInstr32Opcode::Op => self.exec_op_instr(instr)?,
            RvInstr32Opcode::Lui => self.exec_lui_instr(instr)?,
            RvInstr32Opcode::Branch => self.exec_branch_instr(instr)?,
            RvInstr32Opcode::Jalr => self.exec_jalr_instr(instr)?,
            RvInstr32Opcode::Jal => self.exec_jal_instr(instr)?,
            RvInstr32Opcode::System => self.exec_system_instr(instr)?,
            RvInstr32Opcode::Fence => self.exec_fence_instr(instr)?,
            _ => Err(RvException::illegal_instr(instr))?,
        }
        Ok(())
    }
}
