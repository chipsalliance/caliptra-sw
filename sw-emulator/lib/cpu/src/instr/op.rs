/*++

Licensed under the Apache-2.0 license.

File Name:

    op.rs

Abstract:

    File contains implementation of RISCV Register Operation instructions

--*/

use crate::bus::Bus;
use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{
    RvData, RvInstr, RvInstr32OpFunct3, RvInstr32OpFunct7, RvInstr32Opcode, RvInstr32R,
};

impl<TBus: Bus> Cpu<TBus> {
    /// Execute register operation instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_op_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32R(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Op);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::RType(instr));

        let val1 = self.read_xreg(instr.rs1())?;
        let val2 = self.read_xreg(instr.rs2())?;

        let data = match (instr.funct3().into(), instr.funct7().into()) {
            // Add (`add`) instruction
            (RvInstr32OpFunct3::Zero, RvInstr32OpFunct7::Add) => val1.wrapping_add(val2) as RvData,

            // Multiply (`mul`) instruction
            (RvInstr32OpFunct3::Zero, RvInstr32OpFunct7::Mul) => {
                let val1 = val1 as i32;
                let val2 = val2 as i32;
                val1.wrapping_mul(val2) as RvData
            }

            // Subtract (`sub`) instruction
            (RvInstr32OpFunct3::Zero, RvInstr32OpFunct7::Sub) => val1.wrapping_sub(val2) as RvData,

            // Shift Left Logical (`sll`) instruction
            (RvInstr32OpFunct3::One, RvInstr32OpFunct7::Sll) => val1.wrapping_shl(val2) as RvData,

            // Multiply High (`mul`) instruction
            (RvInstr32OpFunct3::One, RvInstr32OpFunct7::Mulh) => {
                let val1 = val1 as i32 as i64;
                let val2 = val2 as i32 as i64;
                (val1.wrapping_mul(val2) >> 32) as RvData
            }

            // Set Less Than (`slt`) instruction
            (RvInstr32OpFunct3::Two, RvInstr32OpFunct7::Slt) => {
                if (val1 as i32) < (val2 as i32) {
                    1
                } else {
                    0
                }
            }

            // Multiply High Signed and Unsigned (`mulhsu`) instruction
            (RvInstr32OpFunct3::Two, RvInstr32OpFunct7::Mulhsu) => {
                let val1 = val1 as i32 as i64 as u64;
                let val2 = val2 as u64;
                (val1.wrapping_mul(val2) >> 32) as RvData
            }

            // Set Less Than Unsigned (`sltu`) instruction
            (RvInstr32OpFunct3::Three, RvInstr32OpFunct7::Sltu) => {
                if val1 < val2 {
                    1
                } else {
                    0
                }
            }

            // Multiply High Unsigned (`mulhu`) instruction
            (RvInstr32OpFunct3::Three, RvInstr32OpFunct7::Mulhu) => {
                let val1 = val1 as u64;
                let val2 = val2 as u64;
                (val1.wrapping_mul(val2) >> 32) as RvData
            }

            // Xor (`xor`) instruction
            (RvInstr32OpFunct3::Four, RvInstr32OpFunct7::Xor) => val1 ^ val2,

            // Division (`div`) instruction
            (RvInstr32OpFunct3::Four, RvInstr32OpFunct7::Div) => {
                let dividend = val1 as i32;
                let divisor = val2 as i32;
                if divisor == 0 {
                    RvData::MAX
                } else if dividend == i32::MIN && divisor == -1 {
                    dividend as RvData
                } else {
                    dividend.wrapping_div(divisor) as RvData
                }
            }

            // Shift Right Logical (`srl`) instruction
            (RvInstr32OpFunct3::Five, RvInstr32OpFunct7::Srl) => val1.wrapping_shr(val2) as RvData,

            // Division Unsigned (`divu`) instruction
            (RvInstr32OpFunct3::Five, RvInstr32OpFunct7::Divu) => {
                let dividend = val1;
                let divisor = val2;
                if divisor == 0 {
                    RvData::MAX
                } else {
                    dividend.wrapping_div(divisor) as RvData
                }
            }

            // Shift Right Arithmetic (`sra`) instruction
            (RvInstr32OpFunct3::Five, RvInstr32OpFunct7::Sra) => {
                (val1 as i32).wrapping_shr(val2) as RvData
            }

            // Or (`or`) instruction
            (RvInstr32OpFunct3::Six, RvInstr32OpFunct7::Or) => val1 | val2,

            // Remainder (`rem`) instruction
            (RvInstr32OpFunct3::Six, RvInstr32OpFunct7::Rem) => {
                let dividend = val1 as i32;
                let divisor = val2 as i32;
                if divisor == 0 {
                    dividend as RvData
                } else if dividend == i32::MIN && divisor == -1 {
                    0
                } else {
                    dividend.wrapping_rem(divisor) as RvData
                }
            }

            // And (`and`) instruction
            (RvInstr32OpFunct3::Seven, RvInstr32OpFunct7::And) => val1 & val2,

            // Remained Unsigned (`remu`) instruction
            (RvInstr32OpFunct3::Seven, RvInstr32OpFunct7::Remu) => {
                let dividend = val1;
                let divisor = val2;
                if divisor == 0 {
                    dividend as RvData
                } else {
                    dividend.wrapping_rem(divisor) as RvData
                }
            }

            // Illegal instruction
            _ => Err(RvException::illegal_instr(instr.0))?,
        };

        self.write_xreg(instr.rd(), data)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_rr_op, test_rr_src12_eq_dest, test_rr_src1_eq_dest, test_rr_src2_eq_dest,
        test_rr_zerodest, test_rr_zerosrc1, test_rr_zerosrc12, test_rr_zerosrc2,
    };

    // ---------------------------------------------------------------------------------------------
    // Tests For Add (`add`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/add.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_add_2, add, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_add_3, add, 0x00000002, 0x00000001, 0x00000001);
    test_rr_op!(test_add_4, add, 0x0000000a, 0x00000003, 0x00000007);
    test_rr_op!(test_add_5, add, 0xFFFF8000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_add_6, add, 0x80000000, 0x80000000, 0x00000000);
    test_rr_op!(test_add_7, add, 0x7FFF8000, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_add_8, add, 0x00007FFF, 0x00000000, 0x00007FFF);
    test_rr_op!(test_add_9, add, 0x7FFFFFFF, 0x7FFFFFFF, 0x00000000);
    test_rr_op!(test_add_10, add, 0x80007FFE, 0x7FFFFFFF, 0x00007FFF);
    test_rr_op!(test_add_11, add, 0x80007FFF, 0x80000000, 0x00007FFF);
    test_rr_op!(test_add_12, add, 0x7FFF7FFF, 0x7FFFFFFF, 0xFFFF8000);
    test_rr_op!(test_add_13, add, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF);
    test_rr_op!(test_add_14, add, 0x00000000, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_add_15, add, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF);
    test_rr_op!(test_add_16, add, 0x80000000, 0x00000001, 0x7FFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_add_17, add, 24, 13, 11);
    test_rr_src2_eq_dest!(test_add_18, add, 25, 14, 11);
    test_rr_src12_eq_dest!(test_add_19, add, 26, 13);

    // Bypassing tests
    test_rr_zerosrc1!(test_add_35, add, 15, 15);
    test_rr_zerosrc2!(test_add_36, add, 32, 32);
    test_rr_zerosrc12!(test_add_37, add, 0);
    test_rr_zerodest!(test_add_38, add, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests For Mul (`mul`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/mul.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_mul_32, mul, 0x00001200, 0x00007e00, 0xb6db6db7);
    test_rr_op!(test_mul_33, mul, 0x00001240, 0x00007Fc0, 0xb6db6db7);
    test_rr_op!(test_mul_2, mul, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_mul_3, mul, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_mul_4, mul, 0x00000015, 0x00000003, 0x00000007);
    test_rr_op!(test_mul_5, mul, 0x00000000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_mul_6, mul, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_mul_7, mul, 0x00000000, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_mul_30, mul, 0x0000FF7F, 0xaaaaaaab, 0x0002Fe7d);
    test_rr_op!(test_mul_31, mul, 0x0000FF7F, 0x0002Fe7d, 0xaaaaaaab);
    test_rr_op!(test_mul_34, mul, 0x00000000, 0xFF000000, 0xFF000000);
    test_rr_op!(test_mul_35, mul, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFF);
    test_rr_op!(test_mul_36, mul, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_mul_37, mul, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_mul_8, mul, 143, 13, 11);
    test_rr_src2_eq_dest!(test_mul_9, mul, 154, 14, 11);
    test_rr_src12_eq_dest!(test_mul_10, mul, 169, 13);

    // Bypassing tests
    test_rr_zerosrc1!(test_mul_26, mul, 0, 31);
    test_rr_zerosrc2!(test_mul_27, mul, 0, 32);
    test_rr_zerosrc12!(test_mul_28, mul, 0);
    test_rr_zerodest!(test_mul_29, mul, 33, 34);

    // ---------------------------------------------------------------------------------------------
    // Tests For Sub (`sub`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sub.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_sub_2, sub, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_sub_3, sub, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_sub_4, sub, 0xFFFFFFFC, 0x00000003, 0x00000007);
    test_rr_op!(test_sub_5, sub, 0x00008000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_sub_6, sub, 0x80000000, 0x80000000, 0x00000000);
    test_rr_op!(test_sub_7, sub, 0x80008000, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_sub_8, sub, 0xFFFF8001, 0x00000000, 0x00007FFF);
    test_rr_op!(test_sub_9, sub, 0x7FFFFFFF, 0x7FFFFFFF, 0x00000000);
    test_rr_op!(test_sub_10, sub, 0x7FFF8000, 0x7FFFFFFF, 0x00007FFF);
    test_rr_op!(test_sub_11, sub, 0x7FFF8001, 0x80000000, 0x00007FFF);
    test_rr_op!(test_sub_12, sub, 0x80007FFF, 0x7FFFFFFF, 0xFFFF8000);
    test_rr_op!(test_sub_13, sub, 0x00000001, 0x00000000, 0xFFFFFFFF);
    test_rr_op!(test_sub_14, sub, 0xFFFFFFFE, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_sub_15, sub, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_sub_16, sub, 2, 13, 11);
    test_rr_src2_eq_dest!(test_sub_17, sub, 3, 14, 11);
    test_rr_src12_eq_dest!(test_sub_18, sub, 0, 13);

    // Bypassing tests
    test_rr_zerosrc1!(test_sub_34, sub, 15, -15i32 as u32);
    test_rr_zerosrc2!(test_sub_35, sub, 32, 32);
    test_rr_zerosrc12!(test_sub_36, sub, 0);
    test_rr_zerodest!(test_sub_37, sub, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests For Shift Logical Left (`sll`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-sofware-src/riscv-tests/blob/master/isa/rv64ui/sll.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_sll_2, sll, 0x00000001, 0x00000001, 0);
    test_rr_op!(test_sll_3, sll, 0x00000002, 0x00000001, 1);
    test_rr_op!(test_sll_4, sll, 0x00000080, 0x00000001, 7);
    test_rr_op!(test_sll_5, sll, 0x00004000, 0x00000001, 14);
    test_rr_op!(test_sll_6, sll, 0x80000000, 0x00000001, 31);
    test_rr_op!(test_sll_7, sll, 0xFFFFFFFF, 0xFFFFFFFF, 0);
    test_rr_op!(test_sll_8, sll, 0xFFFFFFFe, 0xFFFFFFFF, 1);
    test_rr_op!(test_sll_9, sll, 0xFFFFFF80, 0xFFFFFFFF, 7);
    test_rr_op!(test_sll_10, sll, 0xFFFFC000, 0xFFFFFFFF, 14);
    test_rr_op!(test_sll_11, sll, 0x80000000, 0xFFFFFFFF, 31);
    test_rr_op!(test_sll_12, sll, 0x21212121, 0x21212121, 0);
    test_rr_op!(test_sll_13, sll, 0x42424242, 0x21212121, 1);
    test_rr_op!(test_sll_14, sll, 0x90909080, 0x21212121, 7);
    test_rr_op!(test_sll_15, sll, 0x48484000, 0x21212121, 14);
    test_rr_op!(test_sll_16, sll, 0x80000000, 0x21212121, 31);
    test_rr_op!(test_sll_17, sll, 0x21212121, 0x21212121, 0xFFFFFFC0);
    test_rr_op!(test_sll_18, sll, 0x42424242, 0x21212121, 0xFFFFFFC1);
    test_rr_op!(test_sll_19, sll, 0x90909080, 0x21212121, 0xFFFFFFC7);
    test_rr_op!(test_sll_20, sll, 0x48484000, 0x21212121, 0xFFFFFFCe);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_sll_22, sll, 0x00000080, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_sll_23, sll, 0x00004000, 0x00000001, 14);
    test_rr_src12_eq_dest!(test_sll_24, sll, 24, 3);

    // Bypassing tests
    test_rr_zerosrc1!(test_sll_40, sll, 0, 15);
    test_rr_zerosrc2!(test_sll_41, sll, 32, 32);
    test_rr_zerosrc12!(test_sll_42, sll, 0);
    test_rr_zerodest!(test_sll_43, sll, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests For Multiply High (`mulh`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-sofware-src/riscv-tests/blob/master/isa/rv64um/mulh.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_mulh_2, mulh, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_mulh_3, mulh, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_mulh_4, mulh, 0x00000000, 0x00000003, 0x00000007);
    test_rr_op!(test_mulh_5, mulh, 0x00000000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_mulh_6, mulh, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_mulh_7, mulh, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_mulh_30, mulh, 0xFFFF0081, 0xAAAAAAAB, 0x0002FE7D);
    test_rr_op!(test_mulh_31, mulh, 0xFFFF0081, 0x0002FE7D, 0xAAAAAAAB);
    test_rr_op!(test_mulh_32, mulh, 0x00010000, 0xFF000000, 0xFF000000);
    test_rr_op!(test_mulh_33, mulh, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF);
    test_rr_op!(test_mulh_34, mulh, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_mulh_35, mulh, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_mulh_8, mulh, 36608, 13 << 20, 11 << 20);
    test_rr_src2_eq_dest!(test_mulh_9, mulh, 39424, 14 << 20, 11 << 20);
    test_rr_src12_eq_dest!(test_mulh_10, mulh, 43264, 13 << 20);

    // Bypassing tests
    test_rr_zerosrc1!(test_mulh_26, mulh, 0, 31 << 26);
    test_rr_zerosrc2!(test_mulh_27, mulh, 0, 32 << 26);
    test_rr_zerosrc12!(test_mulh_28, mulh, 0);
    test_rr_zerodest!(test_mulh_29, mulh, 33 << 20, 34 << 20);

    // ---------------------------------------------------------------------------------------------
    // Tests For Set Less Than (`slt`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/slt.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_slt_2, slt, 0, 0x00000000, 0x00000000);
    test_rr_op!(test_slt_3, slt, 0, 0x00000001, 0x00000001);
    test_rr_op!(test_slt_4, slt, 1, 0x00000003, 0x00000007);
    test_rr_op!(test_slt_5, slt, 0, 0x00000007, 0x00000003);
    test_rr_op!(test_slt_6, slt, 0, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_slt_7, slt, 1, 0x80000000, 0x00000000);
    test_rr_op!(test_slt_8, slt, 1, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_slt_9, slt, 1, 0x00000000, 0x00007FFF);
    test_rr_op!(test_slt_10, slt, 0, 0x7FFFFFFF, 0x00000000);
    test_rr_op!(test_slt_11, slt, 0, 0x7FFFFFFF, 0x00007FFF);
    test_rr_op!(test_slt_12, slt, 1, 0x80000000, 0x00007FFF);
    test_rr_op!(test_slt_13, slt, 0, 0x7FFFFFFF, 0xFFFF8000);
    test_rr_op!(test_slt_14, slt, 0, 0x00000000, 0xFFFFFFFF);
    test_rr_op!(test_slt_15, slt, 1, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_slt_16, slt, 0, 0xFFFFFFFF, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_slt_17, slt, 0, 14, 13);
    test_rr_src2_eq_dest!(test_slt_18, slt, 1, 11, 13);
    test_rr_src12_eq_dest!(test_slt_19, slt, 0, 13);

    // Bypassing tests
    test_rr_zerosrc1!(test_slt_35, slt, 0, -1i32 as u32);
    test_rr_zerosrc2!(test_slt_36, slt, 1, -1i32 as u32);
    test_rr_zerosrc12!(test_slt_37, slt, 0);
    test_rr_zerodest!(test_slt_38, slt, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests For Multiply High Singed and Unsigned (`mulhsu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/mulhsu.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_mulhsu_2, mulhsu, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_mulhsu_3, mulhsu, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_mulhsu_4, mulhsu, 0x00000000, 0x00000003, 0x00000007);
    test_rr_op!(test_mulhsu_5, mulhsu, 0x00000000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_mulhsu_6, mulhsu, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_mulhsu_7, mulhsu, 0x80004000, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_mulhsu_30, mulhsu, 0xFFFF0081, 0xaaaaaaab, 0x0002fe7d);
    test_rr_op!(test_mulhsu_31, mulhsu, 0x0001fefe, 0x0002fe7d, 0xaaaaaaab);
    test_rr_op!(test_mulhsu_32, mulhsu, 0xFF010000, 0xFF000000, 0xFF000000);
    test_rr_op!(test_mulhsu_33, mulhsu, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF);
    test_rr_op!(test_mulhsu_34, mulhsu, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_mulhsu_35, mulhsu, 0x00000000, 0x00000001, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_mulhsu_8, mulhsu, 36608, 13 << 20, 11 << 20);
    test_rr_src2_eq_dest!(test_mulhsu_9, mulhsu, 39424, 14 << 20, 11 << 20);
    test_rr_src12_eq_dest!(test_mulhsu_10, mulhsu, 43264, 13 << 20);

    // Bypassing tests
    test_rr_zerosrc1!(test_mulhsu_26, mulhsu, 0, 31 << 26);
    test_rr_zerosrc2!(test_mulhsu_27, mulhsu, 0, 32 << 26);
    test_rr_zerosrc12!(test_mulhsu_28, mulhsu, 0);
    test_rr_zerodest!(test_mulhsu_29, mulhsu, 33 << 20, 34 << 20);

    // ---------------------------------------------------------------------------------------------
    // Tests For Set Less Than Unsigned (`sltu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sltu.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_sltu_2, sltu, 0, 0x00000000, 0x00000000);
    test_rr_op!(test_sltu_3, sltu, 0, 0x00000001, 0x00000001);
    test_rr_op!(test_sltu_4, sltu, 1, 0x00000003, 0x00000007);
    test_rr_op!(test_sltu_5, sltu, 0, 0x00000007, 0x00000003);
    test_rr_op!(test_sltu_6, sltu, 1, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_sltu_7, sltu, 0, 0x80000000, 0x00000000);
    test_rr_op!(test_sltu_8, sltu, 1, 0x80000000, 0xFFFF8000);
    test_rr_op!(test_sltu_9, sltu, 1, 0x00000000, 0x00007FFF);
    test_rr_op!(test_sltu_10, sltu, 0, 0x7FFFFFFF, 0x00000000);
    test_rr_op!(test_sltu_11, sltu, 0, 0x7FFFFFFF, 0x00007FFF);
    test_rr_op!(test_sltu_12, sltu, 0, 0x80000000, 0x00007FFF);
    test_rr_op!(test_sltu_13, sltu, 1, 0x7FFFFFFF, 0xFFFF8000);
    test_rr_op!(test_sltu_14, sltu, 1, 0x00000000, 0xFFFFFFFF);
    test_rr_op!(test_sltu_15, sltu, 0, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_sltu_16, sltu, 0, 0xFFFFFFFF, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_sltu_17, sltu, 0, 14, 13);
    test_rr_src2_eq_dest!(test_sltu_18, sltu, 1, 11, 13);
    test_rr_src12_eq_dest!(test_sltu_19, sltu, 0, 13);

    // Bypassing tests
    test_rr_zerosrc1!(test_sltu_35, sltu, 1, -1i32 as u32);
    test_rr_zerosrc2!(test_sltu_36, sltu, 0, -1i32 as u32);
    test_rr_zerosrc12!(test_sltu_37, sltu, 0);
    test_rr_zerodest!(test_sltu_38, sltu, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests For Multiply High Unsigned (`mulhu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/mulhu.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_mulhu_2, mulhu, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_mulhu_3, mulhu, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_mulhu_4, mulhu, 0x00000000, 0x00000003, 0x00000007);

    test_rr_op!(test_mulhu_5, mulhu, 0x00000000, 0x00000000, 0xFFFF8000);
    test_rr_op!(test_mulhu_6, mulhu, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_mulhu_7, mulhu, 0x7FFfC000, 0x80000000, 0xFFFF8000);

    test_rr_op!(test_mulhu_30, mulhu, 0x0001FEFE, 0xAAAAAAAB, 0x0002FE7D);
    test_rr_op!(test_mulhu_31, mulhu, 0x0001FEFE, 0x0002FE7D, 0xAAAAAAAB);

    test_rr_op!(test_mulhu_32, mulhu, 0xFE010000, 0xFF000000, 0xFF000000);

    test_rr_op!(test_mulhu_33, mulhu, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF);
    test_rr_op!(test_mulhu_34, mulhu, 0x00000000, 0xFFFFFFFF, 0x00000001);
    test_rr_op!(test_mulhu_35, mulhu, 0x00000000, 0x00000001, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_mulhu_8, mulhu, 36608, 13 << 20, 11 << 20);
    test_rr_src2_eq_dest!(test_mulhu_9, mulhu, 39424, 14 << 20, 11 << 20);
    test_rr_src12_eq_dest!(test_mulhu_10, mulhu, 43264, 13 << 20);

    // Bypassing tests
    test_rr_zerosrc1!(test_mulhu_26, mulhu, 0, 31 << 26);
    test_rr_zerosrc2!(test_mulhu_27, mulhu, 0, 32 << 26);
    test_rr_zerosrc12!(test_mulhu_28, mulhu, 0);
    test_rr_zerodest!(test_mulhu_29, mulhu, 33 << 20, 34 << 20);

    // ---------------------------------------------------------------------------------------------
    // Tests For Xor (`xor`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/xor.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_xor_2, xor, 0xF00FF00F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_op!(test_xor_3, xor, 0xFF00FF00, 0x0FF00FF0, 0xF0F0F0F0);
    test_rr_op!(test_xor_4, xor, 0x0FF00FF0, 0x00FF00FF, 0x0F0F0F0F);
    test_rr_op!(test_xor_5, xor, 0x00FF00FF, 0xF00FF00F, 0xF0F0F0F0);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_xor_6, xor, 0xF00FF00F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_src2_eq_dest!(test_xor_7, xor, 0xF00FF00F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_src12_eq_dest!(test_xor_8, xor, 0x00000000, 0xFF00FF00);

    // Bypassing tests
    test_rr_zerosrc1!(test_xor_24, xor, 0xFF00FF00, 0xFF00FF00);
    test_rr_zerosrc2!(test_xor_25, xor, 0x00FF00FF, 0x00FF00FF);
    test_rr_zerosrc12!(test_xor_26, xor, 0);
    test_rr_zerodest!(test_xor_27, xor, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests For Division (`div`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/div.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_div_2, div, 3, 20, 6);
    test_rr_op!(test_div_3, div, (-3i32 as u32), (-20i32 as u32), 6);
    test_rr_op!(test_div_4, div, (-3i32 as u32), 20, (-6i32 as u32));
    test_rr_op!(test_div_5, div, 3, (-20i32 as u32), (-6i32 as u32));
    test_rr_op!(
        test_div_6,
        div,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        1
    );
    test_rr_op!(
        test_div_7,
        div,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        (-1i32 as u32)
    );
    test_rr_op!(test_div_8, div, (-1i32 as u32), (-1i32 as u32) << 31, 0);
    test_rr_op!(test_div_9, div, (-1i32 as u32), 1, 0);
    test_rr_op!(test_div_10, div, (-1i32 as u32), 0, 0);

    // ---------------------------------------------------------------------------------------------
    // Tests For Shift Right Logical (`srl`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/srl.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_srl_2, srl, 0x80000000 >> 0, 0x80000000, 0);
    test_rr_op!(test_srl_3, srl, 0x80000000 >> 1, 0x80000000, 1);
    test_rr_op!(test_srl_4, srl, 0x80000000 >> 7, 0x80000000, 7);
    test_rr_op!(test_srl_5, srl, 0x80000000 >> 14, 0x80000000, 14);
    test_rr_op!(test_srl_6, srl, 0x80000001 >> 31, 0x80000001, 31);
    test_rr_op!(test_srl_7, srl, 0xFFFFFFFF >> 0, 0xFFFFFFFF, 0);
    test_rr_op!(test_srl_8, srl, 0xFFFFFFFF >> 1, 0xFFFFFFFF, 1);
    test_rr_op!(test_srl_9, srl, 0xFFFFFFFF >> 7, 0xFFFFFFFF, 7);
    test_rr_op!(test_srl_10, srl, 0xFFFFFFFF >> 14, 0xFFFFFFFF, 14);
    test_rr_op!(test_srl_11, srl, 0xFFFFFFFF >> 31, 0xFFFFFFFF, 31);
    test_rr_op!(test_srl_12, srl, 0x21212121 >> 0, 0x21212121, 0);
    test_rr_op!(test_srl_13, srl, 0x21212121 >> 1, 0x21212121, 1);
    test_rr_op!(test_srl_14, srl, 0x21212121 >> 7, 0x21212121, 7);
    test_rr_op!(test_srl_15, srl, 0x21212121 >> 14, 0x21212121, 14);
    test_rr_op!(test_srl_16, srl, 0x21212121 >> 31, 0x21212121, 31);
    test_rr_op!(test_srl_17, srl, 0x21212121, 0x21212121, 0xFFFFFFC0);
    test_rr_op!(test_srl_18, srl, 0x10909090, 0x21212121, 0xFFFFFFC1);
    test_rr_op!(test_srl_19, srl, 0x00424242, 0x21212121, 0xFFFFFFC7);
    test_rr_op!(test_srl_20, srl, 0x00008484, 0x21212121, 0xFFFFFFCE);
    test_rr_op!(test_srl_21, srl, 0x00000000, 0x21212121, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_srl_22, srl, 0x01000000, 0x80000000, 7);
    test_rr_src2_eq_dest!(test_srl_23, srl, 0x00020000, 0x80000000, 14);
    test_rr_src12_eq_dest!(test_srl_24, srl, 0, 7);

    // Bypassing tests
    test_rr_zerosrc1!(test_srl_40, srl, 0, 15);
    test_rr_zerosrc2!(test_srl_41, srl, 32, 32);
    test_rr_zerosrc12!(test_srl_42, srl, 0);
    test_rr_zerodest!(test_srl_43, srl, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests For Division Unsigned (`divu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/divu.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_divu_2, divu, 3, 20, 6);
    test_rr_op!(test_divu_3, divu, 715827879, (-20i32 as u32), 6);
    test_rr_op!(test_divu_4, divu, 0, 20, (-6i32 as u32));
    test_rr_op!(test_divu_5, divu, 0, (-20i32 as u32), (-6i32 as u32));
    test_rr_op!(
        test_divu_6,
        divu,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        1
    );
    test_rr_op!(test_divu_7, divu, 0, (-1i32 as u32) << 31, (-1i32 as u32));
    test_rr_op!(test_divu_8, divu, (-1i32 as u32), (-1i32 as u32) << 31, 0);
    test_rr_op!(test_divu_9, divu, (-1i32 as u32), 1, 0);
    test_rr_op!(test_divu_10, divu, (-1i32 as u32), 0, 0);

    // ---------------------------------------------------------------------------------------------
    // Tests For Shift Right Arithmetic (`sra`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sra.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_sra_2, sra, 0x80000000, 0x80000000, 0);
    test_rr_op!(test_sra_3, sra, 0xC0000000, 0x80000000, 1);
    test_rr_op!(test_sra_4, sra, 0xFF000000, 0x80000000, 7);
    test_rr_op!(test_sra_5, sra, 0xFFFE0000, 0x80000000, 14);
    test_rr_op!(test_sra_6, sra, 0xFFFFFFFF, 0x80000001, 31);
    test_rr_op!(test_sra_7, sra, 0x7FFFFFFF, 0x7FFFFFFF, 0);
    test_rr_op!(test_sra_8, sra, 0x3FFFFFFF, 0x7FFFFFFF, 1);
    test_rr_op!(test_sra_9, sra, 0x00FFFFFF, 0x7FFFFFFF, 7);
    test_rr_op!(test_sra_10, sra, 0x0001FFFF, 0x7FFFFFFF, 14);
    test_rr_op!(test_sra_11, sra, 0x00000000, 0x7FFFFFFF, 31);
    test_rr_op!(test_sra_12, sra, 0x81818181, 0x81818181, 0);
    test_rr_op!(test_sra_13, sra, 0xC0C0C0C0, 0x81818181, 1);
    test_rr_op!(test_sra_14, sra, 0xFF030303, 0x81818181, 7);
    test_rr_op!(test_sra_15, sra, 0xFFFE0606, 0x81818181, 14);
    test_rr_op!(test_sra_16, sra, 0xFFFFFFFF, 0x81818181, 31);
    test_rr_op!(test_sra_17, sra, 0x81818181, 0x81818181, 0xFFFFFFC0);
    test_rr_op!(test_sra_18, sra, 0xC0C0C0C0, 0x81818181, 0xFFFFFFC1);
    test_rr_op!(test_sra_19, sra, 0xFF030303, 0x81818181, 0xFFFFFFC7);
    test_rr_op!(test_sra_20, sra, 0xFFFE0606, 0x81818181, 0xFFFFFFCe);
    test_rr_op!(test_sra_21, sra, 0xFFFFFFFF, 0x81818181, 0xFFFFFFFF);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_sra_22, sra, 0xFF000000, 0x80000000, 7);
    test_rr_src2_eq_dest!(test_sra_23, sra, 0xFFFE0000, 0x80000000, 14);
    test_rr_src12_eq_dest!(test_sra_24, sra, 0, 7);

    // Bypassing tests
    test_rr_zerosrc1!(test_sra_40, sra, 0, 15);
    test_rr_zerosrc2!(test_sra_41, sra, 32, 32);
    test_rr_zerosrc12!(test_sra_42, sra, 0);
    test_rr_zerodest!(test_sra_43, sra, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests For Or (`or`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/or.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_or_2, or, 0xFF0FFF0F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_op!(test_or_3, or, 0xFFF0FFF0, 0x0FF00FF0, 0xF0F0F0F0);
    test_rr_op!(test_or_4, or, 0x0FFF0FFf, 0x00FF00FF, 0x0F0F0F0F);
    test_rr_op!(test_or_5, or, 0xF0FFF0FF, 0xF00FF00F, 0xF0F0F0F0);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_or_6, or, 0xFF0FFF0F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_src2_eq_dest!(test_or_7, or, 0xFF0FFF0F, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_src12_eq_dest!(test_or_8, or, 0xFF00FF00, 0xFF00FF00);

    // Bypassing tests
    test_rr_zerosrc1!(test_or_24, or, 0xFF00FF00, 0xFF00FF00);
    test_rr_zerosrc2!(test_or_25, or, 0x00FF00FF, 0x00FF00FF);
    test_rr_zerosrc12!(test_or_26, or, 0);
    test_rr_zerodest!(test_or_27, or, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests For Remainder (`rem`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/rem.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_rem_2, rem, 2, 20, 6);
    test_rr_op!(test_rem_3, rem, (-2i32 as u32), (-20i32 as u32), 6);
    test_rr_op!(test_rem_4, rem, 2, 20, (-6i32 as u32));
    test_rr_op!(
        test_rem_5,
        rem,
        (-2i32 as u32),
        (-20i32 as u32),
        (-6i32 as u32)
    );
    test_rr_op!(test_rem_6, rem, 0, (-1i32 as u32) << 31, 1);
    test_rr_op!(test_rem_7, rem, 0, (-1i32 as u32) << 31, (-1i32 as u32));
    test_rr_op!(
        test_rem_8,
        rem,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        0
    );
    test_rr_op!(test_rem_9, rem, 1, 1, 0);
    test_rr_op!(test_rem_10, rem, 0, 0, 0);

    // ---------------------------------------------------------------------------------------------
    // Tests For And (`and`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/and.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_and_2, and, 0x0F000F00, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_op!(test_and_3, and, 0x00F000F0, 0x0FF00FF0, 0xF0F0F0F0);
    test_rr_op!(test_and_4, and, 0x000F000F, 0x00FF00FF, 0x0F0F0F0F);
    test_rr_op!(test_and_5, and, 0xF000F000, 0xF00FF00F, 0xF0F0F0F0);

    // Source/Destination tests
    test_rr_src1_eq_dest!(test_and_6, and, 0x0F000F00, 0xFF00FF00, 0x0F0F0F0F);
    test_rr_src2_eq_dest!(test_and_7, and, 0x00F000F0, 0x0FF00FF0, 0xF0F0F0F0);
    test_rr_src12_eq_dest!(test_and_8, and, 0xFF00FF00, 0xFF00FF00);

    // Bypassing tests
    test_rr_zerosrc1!(test_and_24, and, 0, 0xFF00FF00);
    test_rr_zerosrc2!(test_and_25, and, 0, 0x00FF00FF);
    test_rr_zerosrc12!(test_and_26, and, 0);
    test_rr_zerodest!(test_and_27, and, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests For Remainder Unsigned (`remu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64um/rem.S
    // ---------------------------------------------------------------------------------------------

    // Arithmetic tests
    test_rr_op!(test_remu_2, remu, 2, 20, 6);
    test_rr_op!(test_remu_3, remu, 2, (-20i32 as u32), 6);
    test_rr_op!(test_remu_4, remu, 20, 20, (-6i32 as u32));
    test_rr_op!(
        test_remu_5,
        remu,
        (-20i32 as u32),
        (-20i32 as u32),
        (-6i32 as u32)
    );
    test_rr_op!(test_remu_6, remu, 0, (-1i32 as u32) << 31, 1);
    test_rr_op!(
        test_remu_7,
        remu,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        (-1i32 as u32)
    );
    test_rr_op!(
        test_remu_8,
        remu,
        (-1i32 as u32) << 31,
        (-1i32 as u32) << 31,
        0
    );
    test_rr_op!(test_remu_9, remu, 1, 1, 0);
    test_rr_op!(test_remu_10, remu, 0, 0, 0);
}
