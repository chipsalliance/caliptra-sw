/*++

Licensed under the Apache-2.0 license.

File Name:

    op_imm.rs

Abstract:

    File contains implementation of RISCV Immediate instructions.

References:
    https://riscv.org/wp-content/uploads/2019/06/riscv-spec.pdf
    https://github.com/d0iasm/rvemu for arithmetic operations.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32I, RvInstr32OpImmFunct3, RvInstr32OpImmFunct7, RvInstr32Opcode};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvData, RvException};

impl<TBus: Bus> Cpu<TBus> {
    /// Execute immediate instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_op_imm_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::OpImm);

        // Read the content of source register
        let reg = self.read_xreg(instr.rs())?;

        let data = if let Some(data) = self.exec_bit_instr_op_imm(instr, reg) {
            data
        } else {
            match instr.funct3().into() {
                // Add Immediate (`addi`) Instruction
                RvInstr32OpImmFunct3::Addi => reg.wrapping_add(instr.imm() as u32) as RvData,

                RvInstr32OpImmFunct3::Sli => {
                    match instr.funct7().into() {
                        // Shift Left Logical Immediate (`slli`) Instruction
                        RvInstr32OpImmFunct7::Slli => reg.wrapping_shl(instr.shamt()) as RvData,

                        // Illegal Instruction
                        _ => Err(RvException::illegal_instr(instr.0))?,
                    }
                }

                // Set Less Than Immediate (`slti`) Instruction
                RvInstr32OpImmFunct3::Slti => {
                    if (reg as i32) < instr.imm() {
                        1
                    } else {
                        0
                    }
                }

                // Set Less Than Immediate Unsigned (`sltiu`) Instruction
                RvInstr32OpImmFunct3::Sltiu => {
                    if reg < instr.imm() as u32 {
                        1
                    } else {
                        0
                    }
                }

                // Xor Immediate (`xori`) Instruction
                RvInstr32OpImmFunct3::Xori => reg ^ instr.imm() as u32,

                // Shift Right Immediate Instruction
                RvInstr32OpImmFunct3::Sri => {
                    match instr.funct7().into() {
                        // Shift Right Logical Immediate (`srli`) Instruction
                        RvInstr32OpImmFunct7::Srli => reg.wrapping_shr(instr.shamt()) as RvData,

                        // Shift Right Arithmetic Immediate (`srai`) Instruction
                        RvInstr32OpImmFunct7::Srai => {
                            (reg as i32).wrapping_shr(instr.shamt()) as RvData
                        }

                        // Illegal Instruction
                        _ => Err(RvException::illegal_instr(instr.0))?,
                    }
                }

                // Or Immediate (`ori`) Instruction
                RvInstr32OpImmFunct3::Ori => reg | instr.imm() as u32,

                // And Immediate (`ori`) Instruction
                RvInstr32OpImmFunct3::Andi => reg & instr.imm() as u32,

                // Illegal Instruction
                _ => Err(RvException::illegal_instr(instr.0))?,
            }
        };

        // Save the contents to register
        self.write_xreg(instr.rd(), data)
    }
}

#[cfg(test)]
#[allow(clippy::identity_op)]
mod tests {
    use crate::{test_imm_op, test_imm_src1_eq_dest, test_imm_zero_dest, test_imm_zero_src1};

    // ---------------------------------------------------------------------------------------------
    // Tests for Add Immediate (`addi`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/addi.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_imm_op!(test_addi_2, addi, 0x0000_0000, 0x0000_0000, 0x000);
    test_imm_op!(test_addi_3, addi, 0x0000_0002, 0x0000_0001, 0x001);
    test_imm_op!(test_addi_4, addi, 0x0000_000A, 0x0000_0003, 0x007);
    test_imm_op!(test_addi_5, addi, 0xFFFF_F800, 0x0000_0000, 0x800);
    test_imm_op!(test_addi_6, addi, 0x8000_0000, 0x8000_0000, 0x000);
    test_imm_op!(test_addi_7, addi, 0x7FFF_F800, 0x8000_0000, 0x800);
    test_imm_op!(test_addi_8, addi, 0x0000_07FF, 0x0000_0000, 0x7FF);
    test_imm_op!(test_addi_9, addi, 0x7FFF_FFFF, 0x7FFF_FFFF, 0x000);
    test_imm_op!(test_addi_10, addi, 0x8000_07FE, 0x7FFF_FFFF, 0x7FF);
    test_imm_op!(test_addi_11, addi, 0x8000_07FF, 0x8000_0000, 0x7FF);
    test_imm_op!(test_addi_12, addi, 0x7FFF_F7FF, 0x7FFF_FFFF, 0x800);
    test_imm_op!(test_addi_13, addi, 0xFFFF_FFFF, 0x0000_0000, 0xFFF);
    test_imm_op!(test_addi_14, addi, 0x0000_0000, 0xFFFF_FFFF, 0x001);
    test_imm_op!(test_addi_15, addi, 0xFFFF_FFFE, 0xFFFF_FFFF, 0xFFF);
    test_imm_op!(test_addi_16, addi, 0x8000_0000, 0x7FFF_FFFF, 0x001);
    test_imm_src1_eq_dest!(test_addi_17, addi, 24, 13, 11);
    test_imm_zero_src1!(test_addi_24, addi, 32, 32);
    test_imm_zero_dest!(test_addi_25, addi, 33, 50);

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift Logical Left Immediate (`slli`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/slli.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_imm_op!(test_slli_2, slli, 0x0000_0001, 0x0000_0001, 0);
    test_imm_op!(test_slli_3, slli, 0x0000_0002, 0x0000_0001, 1);
    test_imm_op!(test_slli_4, slli, 0x0000_0080, 0x0000_0001, 7);
    test_imm_op!(test_slli_5, slli, 0x0000_4000, 0x0000_0001, 14);
    test_imm_op!(test_slli_6, slli, 0x8000_0000, 0x0000_0001, 31);
    test_imm_op!(test_slli_7, slli, 0xFFFF_FFFF, 0xFFFF_FFFF, 0);
    test_imm_op!(test_slli_8, slli, 0xFFFF_FFFE, 0xFFFF_FFFF, 1);
    test_imm_op!(test_slli_9, slli, 0xFFFF_FF80, 0xFFFF_FFFF, 7);
    test_imm_op!(test_slli_10, slli, 0xFFFF_C000, 0xFFFF_FFFF, 14);
    test_imm_op!(test_slli_11, slli, 0x8000_0000, 0xFFFF_FFFF, 31);
    test_imm_op!(test_slli_12, slli, 0x2121_2121, 0x2121_2121, 0);
    test_imm_op!(test_slli_13, slli, 0x4242_4242, 0x2121_2121, 1);
    test_imm_op!(test_slli_14, slli, 0x9090_9080, 0x2121_2121, 7);
    test_imm_op!(test_slli_15, slli, 0x4848_4000, 0x2121_2121, 14);
    test_imm_op!(test_slli_16, slli, 0x8000_0000, 0x2121_2121, 31);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_slli_17, slli, 0x0000_0080, 0x0000_0001, 7);

    // Bypassing tests
    test_imm_zero_src1!(test_slli_24, slli, 0, 31);
    test_imm_zero_dest!(test_slli_25, slli, 33, 20);

    // ---------------------------------------------------------------------------------------------
    // Tests for Set Less Than Immediate (`slti`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/slti.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_imm_op!(test_slti_2, slti, 0, 0x0000_0000, 0x000);
    test_imm_op!(test_slti_3, slti, 0, 0x0000_0001, 0x001);
    test_imm_op!(test_slti_4, slti, 1, 0x0000_0003, 0x007);
    test_imm_op!(test_slti_5, slti, 0, 0x0000_0007, 0x003);
    test_imm_op!(test_slti_6, slti, 0, 0x0000_0000, 0x800);
    test_imm_op!(test_slti_7, slti, 1, 0x8000_0000, 0x000);
    test_imm_op!(test_slti_8, slti, 1, 0x8000_0000, 0x800);
    test_imm_op!(test_slti_9, slti, 1, 0x0000_0000, 0x7FF);
    test_imm_op!(test_slti_10, slti, 0, 0x7FFF_FFFF, 0x000);
    test_imm_op!(test_slti_11, slti, 0, 0x7FFF_FFFF, 0x7FF);
    test_imm_op!(test_slti_12, slti, 1, 0x8000_0000, 0x7FF);
    test_imm_op!(test_slti_13, slti, 0, 0x7FFF_FFFF, 0x800);
    test_imm_op!(test_slti_14, slti, 0, 0x0000_0000, 0xFFF);
    test_imm_op!(test_slti_15, slti, 1, 0xFFFF_FFFF, 0x001);
    test_imm_op!(test_slti_16, slti, 0, 0xFFFF_FFFF, 0xFFF);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_slti_17, slti, 1, 11, 13);

    // Bypassing tests
    test_imm_zero_src1!(test_slti_24, slti, 0, 0xFFF);
    test_imm_zero_dest!(test_slti_25, slti, 0x00FF_00FF, 0xFFF);

    // ---------------------------------------------------------------------------------------------
    // Tests for Set Less Than Immediate Unsigned (`sltiu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sltiu.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_imm_op!(test_sltiu_2, sltiu, 0, 0x0000_0000, 0x000);
    test_imm_op!(test_sltiu_3, sltiu, 0, 0x0000_0001, 0x001);
    test_imm_op!(test_sltiu_4, sltiu, 1, 0x0000_0003, 0x007);
    test_imm_op!(test_sltiu_5, sltiu, 0, 0x0000_0007, 0x003);
    test_imm_op!(test_sltiu_6, sltiu, 1, 0x0000_0000, 0x800);
    test_imm_op!(test_sltiu_7, sltiu, 0, 0x8000_0000, 0x000);
    test_imm_op!(test_sltiu_8, sltiu, 1, 0x8000_0000, 0x800);
    test_imm_op!(test_sltiu_9, sltiu, 1, 0x0000_0000, 0x7FF);
    test_imm_op!(test_sltiu_10, sltiu, 0, 0x7FFF_FFFF, 0x000);
    test_imm_op!(test_sltiu_11, sltiu, 0, 0x7FFF_FFFF, 0x7FF);
    test_imm_op!(test_sltiu_12, sltiu, 0, 0x8000_0000, 0x7FF);
    test_imm_op!(test_sltiu_13, sltiu, 1, 0x7FFF_FFFF, 0x800);
    test_imm_op!(test_sltiu_14, sltiu, 1, 0x0000_0000, 0xFFF);
    test_imm_op!(test_sltiu_15, sltiu, 0, 0xFFFF_FFFF, 0x001);
    test_imm_op!(test_sltiu_16, sltiu, 0, 0xFFFF_FFFF, 0xFFF);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_sltiu_17, sltiu, 1, 11, 13);

    // Bypassing tests
    test_imm_zero_src1!(test_sltiu_24, sltiu, 1, 0xFFF);
    test_imm_zero_dest!(test_sltiu_25, sltiu, 0x00FF_00FF, 0xFFF);

    // ---------------------------------------------------------------------------------------------
    // Tests for Xor Immediate (`xori`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/xori.S
    // ---------------------------------------------------------------------------------------------

    // Logical tests
    test_imm_op!(test_xori_2, xori, 0xFF00_F00F, 0x00FF_0F00, 0xF0F);
    test_imm_op!(test_xori_3, xori, 0x0FF0_0F00, 0x0FF0_0FF0, 0x0F0);
    test_imm_op!(test_xori_4, xori, 0x00FF_0FF0, 0x00FF_08FF, 0x70F);
    test_imm_op!(test_xori_5, xori, 0xF00F_F0FF, 0xF00F_F00F, 0x0F0);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_xori_6, xori, 0xFF00_F00F, 0xFF00_F700, 0x70F);

    // Bypassing tests
    test_imm_zero_src1!(test_xori_13, xori, 0x0F0, 0x0F0);
    test_imm_zero_dest!(test_xori_14, xori, 0x00FF_00FF, 0x70F);

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift Right Logical Immediate (`srli`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/srli.S
    // ---------------------------------------------------------------------------------------------

    // Logical tests
    test_imm_op!(test_srli_2, srli, 0x8000_0000 >> 0, 0x8000_0000, 0);
    test_imm_op!(test_srli_3, srli, 0x8000_0000 >> 1, 0x8000_0000, 1);
    test_imm_op!(test_srli_4, srli, 0x8000_0000 >> 7, 0x8000_0000, 7);
    test_imm_op!(test_srli_5, srli, 0x8000_0000 >> 14, 0x8000_0000, 14);
    test_imm_op!(test_srli_6, srli, 0x8000_0001 >> 31, 0x8000_0001, 31);
    test_imm_op!(test_srli_7, srli, 0xFFFF_FFFF >> 0, 0xFFFF_FFFF, 0);
    test_imm_op!(test_srli_8, srli, 0xFFFF_FFFF >> 1, 0xFFFF_FFFF, 1);
    test_imm_op!(test_srli_9, srli, 0xFFFF_FFFF >> 7, 0xFFFF_FFFF, 7);
    test_imm_op!(test_srli_10, srli, 0xFFFF_FFFF >> 14, 0xFFFF_FFFF, 14);
    test_imm_op!(test_srli_11, srli, 0xFFFF_FFFF >> 31, 0xFFFF_FFFF, 31);
    test_imm_op!(test_srli_12, srli, 0x2121_2121 >> 0, 0x2121_2121, 0);
    test_imm_op!(test_srli_13, srli, 0x2121_2121 >> 1, 0x2121_2121, 1);
    test_imm_op!(test_srli_14, srli, 0x2121_2121 >> 7, 0x2121_2121, 7);
    test_imm_op!(test_srli_15, srli, 0x2121_2121 >> 14, 0x2121_2121, 14);
    test_imm_op!(test_srli_16, srli, 0x2121_2121 >> 31, 0x2121_2121, 31);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_srli_17, srli, 0x0100_0000, 0x8000_0000, 7);

    // Bypassing tests
    test_imm_zero_src1!(test_srli_24, srli, 0, 4);
    test_imm_zero_dest!(test_srli_25, srli, 33, 10);

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift Right Arithmetic Immediate (`srli`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/srai.S
    // ---------------------------------------------------------------------------------------------

    // Logical tests
    test_imm_op!(test_srai_2, srai, 0x0000_0000, 0x0000_0000, 0);
    test_imm_op!(test_srai_3, srai, 0xC000_0000, 0x8000_0000, 1);
    test_imm_op!(test_srai_4, srai, 0xFF00_0000, 0x8000_0000, 7);
    test_imm_op!(test_srai_5, srai, 0xFFFE_0000, 0x8000_0000, 14);
    test_imm_op!(test_srai_6, srai, 0xFFFF_FFFF, 0x8000_0001, 31);
    test_imm_op!(test_srai_7, srai, 0x7FFF_FFFF, 0x7FFF_FFFF, 0);
    test_imm_op!(test_srai_8, srai, 0x3FFF_FFFF, 0x7FFF_FFFF, 1);
    test_imm_op!(test_srai_9, srai, 0x00FF_FFFF, 0x7FFF_FFFF, 7);
    test_imm_op!(test_srai_10, srai, 0x0001_FFFF, 0x7FFF_FFFF, 14);
    test_imm_op!(test_srai_11, srai, 0x0000_0000, 0x7FFF_FFFF, 31);
    test_imm_op!(test_srai_12, srai, 0x8181_8181, 0x8181_8181, 0);
    test_imm_op!(test_srai_13, srai, 0xC0C0_C0C0, 0x8181_8181, 1);
    test_imm_op!(test_srai_14, srai, 0xFF03_0303, 0x8181_8181, 7);
    test_imm_op!(test_srai_15, srai, 0xFFFE_0606, 0x8181_8181, 14);
    test_imm_op!(test_srai_16, srai, 0xFFFF_FFFF, 0x8181_8181, 31);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_srai_17, srai, 0xFF00_0000, 0x8000_0000, 7);

    // Bypassing tests
    test_imm_zero_src1!(test_srai_24, srai, 0, 4);
    test_imm_zero_dest!(test_srai_25, srai, 33, 10);

    // ---------------------------------------------------------------------------------------------
    // Tests For Or Immediate (`ori`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/ori.S
    // ---------------------------------------------------------------------------------------------

    // Logical tests
    test_imm_op!(test_ori_2, ori, 0xFFFF_FF0F, 0xFF00_FF00, 0xF0F);
    test_imm_op!(test_ori_3, ori, 0x0FF0_0FF0, 0x0FF0_0FF0, 0x0F0);
    test_imm_op!(test_ori_4, ori, 0x00FF_07FF, 0x00FF_00FF, 0x70F);
    test_imm_op!(test_ori_5, ori, 0xF00F_F0FF, 0xF00F_F00F, 0x0F0);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_ori_6, ori, 0xFF00_FFF0, 0xFF00_FF00, 0x0F0);

    // Bypassing tests
    test_imm_zero_src1!(test_ori_7, ori, 0x0F0, 0x0F0);
    test_imm_zero_dest!(test_ori_14, ori, 0x00FF_00FF, 0x70F);

    // ---------------------------------------------------------------------------------------------
    // Tests For And Immediate (`andi`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/andi.S
    // ---------------------------------------------------------------------------------------------

    // Logical tests
    test_imm_op!(test_andi_2, andi, 0xFF00FF00, 0xFF00FF00, 0xF0F);
    test_imm_op!(test_andi_3, andi, 0x000000F0, 0x0FF00FF0, 0x0F0);
    test_imm_op!(test_andi_4, andi, 0x0000000F, 0x00FF00FF, 0x70F);
    test_imm_op!(test_andi_5, andi, 0x00000000, 0xF00FF00F, 0x0F0);

    // Source/Destination tests
    test_imm_src1_eq_dest!(test_andi_6, andi, 0x00000000, 0xFF00FF00, 0x0F0);

    // Bypassing tests
    test_imm_zero_src1!(test_andi_13, andi, 0, 0x0F0);
    test_imm_zero_dest!(test_andi_14, andi, 0x00FF00FF, 0x70F);
}
