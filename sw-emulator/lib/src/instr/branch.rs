/*++

Licensed under the Apache-2.0 license.

File Name:

    branch.rs

Abstract:

    File contains implementation of branch instructions.

--*/

use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{RvInstr, RvInstr32B, RvInstr32BranchFunct3, RvInstr32Opcode};

impl Cpu {
    /// Execute branch Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_branch_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32B(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Branch);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::BType(instr));

        let val1 = self.read_xreg(instr.rs1())?;
        let val2 = self.read_xreg(instr.rs2())?;
        let pc = self.read_pc();

        match instr.funct3().into() {
            // Branch on equal to
            RvInstr32BranchFunct3::Beq => {
                if val1 == val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Branch on not equal to
            RvInstr32BranchFunct3::Bne => {
                if val1 != val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Branch on less than
            RvInstr32BranchFunct3::Blt => {
                let val1 = val1 as i32;
                let val2 = val2 as i32;
                if val1 < val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Branch on greater than equal
            RvInstr32BranchFunct3::Bge => {
                let val1 = val1 as i32;
                let val2 = val2 as i32;
                if val1 >= val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Branch on less than unsigned
            RvInstr32BranchFunct3::Bltu => {
                if val1 < val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Branch on greater than unsigned
            RvInstr32BranchFunct3::Bgeu => {
                if val1 >= val2 {
                    self.write_pc(pc.wrapping_add(instr.imm()).wrapping_sub(4));
                }
            }

            // Illegal instruction
            _ => Err(RvException::illegal_instr(instr.0))?,
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_br2_op_not_taken, test_br2_op_taken};

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on equal (`beq`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/beq.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_beq_2, beq, 0, 0);
    test_br2_op_taken!(test_beq_3, beq, 1, 1);
    test_br2_op_taken!(test_beq_4, beq, -1i32 as u32, -1i32 as u32);
    test_br2_op_not_taken!(test_beq_5, beq, 0, 1);
    test_br2_op_not_taken!(test_beq_6, beq, 1, 0);
    test_br2_op_not_taken!(test_beq_7, beq, -1i32 as u32, 1);
    test_br2_op_not_taken!(test_beq_8, beq, 1, -1i32 as u32);

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on not equal (`bne`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/bne.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_bne_2, bne, 0, 1);
    test_br2_op_taken!(test_bne_3, bne, 1, 0);
    test_br2_op_taken!(test_bne_4, bne, -1i32 as u32, 1);
    test_br2_op_taken!(test_bne_5, bne, 1, -1i32 as u32);
    test_br2_op_not_taken!(test_bne_6, bne, 0, 0);
    test_br2_op_not_taken!(test_bne_7, bne, 1, 1);
    test_br2_op_not_taken!(test_bne_8, bne, -1i32 as u32, -1i32 as u32);

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on less than (`blt`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/blt.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_blt_2, blt, 0, 1);
    test_br2_op_taken!(test_blt_3, blt, -1i32 as u32, 1);
    test_br2_op_taken!(test_blt_4, blt, -2i32 as u32, -1i32 as u32);
    test_br2_op_not_taken!(test_blt_5, blt, 1, 0);
    test_br2_op_not_taken!(test_blt_6, blt, 1, -1i32 as u32);
    test_br2_op_not_taken!(test_blt_7, blt, -1i32 as u32, -2i32 as u32);
    test_br2_op_not_taken!(test_blt_8, blt, 1, -2i32 as u32);

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on greater than equal (`bge`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/bge.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_bge_2, bge, 0, 0);
    test_br2_op_taken!(test_bge_3, bge, 1, 1);
    test_br2_op_taken!(test_bge_4, bge, -1i32 as u32, -1i32 as u32);
    test_br2_op_taken!(test_bge_5, bge, 1, 0);
    test_br2_op_taken!(test_bge_6, bge, 1, -1i32 as u32);
    test_br2_op_taken!(test_bge_7, bge, -1i32 as u32, -2i32 as u32);
    test_br2_op_not_taken!(test_bge_8, bge, 0, 1);
    test_br2_op_not_taken!(test_bge_9, bge, -1i32 as u32, 1);
    test_br2_op_not_taken!(test_bge_10, bge, -2i32 as u32, -1i32 as u32);
    test_br2_op_not_taken!(test_bge_11, bge, -2i32 as u32, 1);

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on less than unsigned (`bltu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/bltu.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_bltu_2, bltu, 0x00000000, 0x00000001);
    test_br2_op_taken!(test_bltu_3, bltu, 0xfffffffe, 0xffffffff);
    test_br2_op_taken!(test_bltu_4, bltu, 0x00000000, 0xffffffff);
    test_br2_op_not_taken!(test_bltu_5, bltu, 0x00000001, 0x00000000);
    test_br2_op_not_taken!(test_bltu_6, bltu, 0xffffffff, 0xfffffffe);
    test_br2_op_not_taken!(test_bltu_7, bltu, 0xffffffff, 0x00000000);
    test_br2_op_not_taken!(test_bltu_8, bltu, 0x80000000, 0x7fffffff);

    // ---------------------------------------------------------------------------------------------
    // Tests For Branch on greater than equal unsigned (`bgeu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/bgeu.S
    // ---------------------------------------------------------------------------------------------

    test_br2_op_taken!(test_bgeu_2, bgeu, 0x00000000, 0x00000000);
    test_br2_op_taken!(test_bgeu_3, bgeu, 0x00000001, 0x00000001);
    test_br2_op_taken!(test_bgeu_4, bgeu, 0xffffffff, 0xffffffff);
    test_br2_op_taken!(test_bgeu_5, bgeu, 0x00000001, 0x00000000);
    test_br2_op_taken!(test_bgeu_6, bgeu, 0xffffffff, 0xfffffffe);
    test_br2_op_taken!(test_bgeu_7, bgeu, 0xffffffff, 0x00000000);
    test_br2_op_not_taken!(test_bgeu_8, bgeu, 0x00000000, 0x00000001);
    test_br2_op_not_taken!(test_bgeu_9, bgeu, 0xfffffffe, 0xffffffff);
    test_br2_op_not_taken!(test_bgeu_10, bgeu, 0x00000000, 0xffffffff);
    test_br2_op_not_taken!(test_bgeu_11, bgeu, 0x7fffffff, 0x80000000);
}
