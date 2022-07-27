/*++

Licensed under the Apache-2.0 license.

File Name:

    load.rs

Abstract:

    File contains implementation of RISCV Load Instructions.

--*/

use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{
    RvAddr, RvData, RvInstr, RvInstr32I, RvInstr32LoadFunct3, RvInstr32Opcode, RvSize,
};

impl Cpu {
    /// Execute load instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_load_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Load);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::IType(instr));

        // Calculate the address to load the data from
        let addr = (self.read_xreg(instr.rs())? as RvAddr).wrapping_add(instr.imm() as RvAddr);

        // Read the data
        let data = match instr.funct3().into() {
            // Load Byte ('lb') Instruction
            RvInstr32LoadFunct3::Lb => self.read(RvSize::Byte, addr)? as i8 as i32 as RvData,

            // Load Half Word ('lh') Instruction
            RvInstr32LoadFunct3::Lh => self.read(RvSize::HalfWord, addr)? as i16 as i32 as RvData,

            // Load Word ('lw') Instruction
            RvInstr32LoadFunct3::Lw => self.read(RvSize::Word, addr)? as i32 as RvData,

            // Load Byte Unsigned ('lbu') Instruction
            RvInstr32LoadFunct3::Lbu => self.read(RvSize::Byte, addr)?,

            // Load Half Word Unsigned ('lhu') Instruction
            RvInstr32LoadFunct3::Lhu => self.read(RvSize::HalfWord, addr)?,

            // Illegal Instruction
            _ => Err(RvException::illegal_instr(instr.0))?,
        };

        // Save the contents to register
        self.write_xreg(instr.rd(), data)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{lb, lbu, lh, lhu, lw};
    use crate::xreg_file::XReg;
    use crate::{data, db, dh, dw, isa_test, test_ld_op, text};
    use lazy_static::lazy_static;

    // ---------------------------------------------------------------------------------------------
    // Tests for Load Byte (`lb`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lb.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LB: Vec<u8> = data![db!(0xFF); db!(0x00); db!(0xF0); db!(0x0F);];
    }

    // Basic Tests
    test_ld_op!(test_lb_2, lb, 0xFFFF_FFFF, 0, 0x1000, DATA_LB);
    test_ld_op!(test_lb_3, lb, 0x0000_0000, 1, 0x1000, DATA_LB);
    test_ld_op!(test_lb_4, lb, 0xFFFF_FFF0, 2, 0x1000, DATA_LB);
    test_ld_op!(test_lb_5, lb, 0x0000_000F, 3, 0x1000, DATA_LB);

    // Test with negative offset
    test_ld_op!(test_lb_6, lb, 0xFFFF_FFFF, -3, 0x1003, DATA_LB);
    test_ld_op!(test_lb_7, lb, 0x0000_0000, -2, 0x1003, DATA_LB);
    test_ld_op!(test_lb_8, lb, 0xFFFF_FFF0, -1, 0x1003, DATA_LB);
    test_ld_op!(test_lb_9, lb, 0x0000_000F, -0, 0x1003, DATA_LB);

    // Test with negative base
    #[test]
    fn test_lb_10() {
        isa_test!(
            0x0000 => text![
                lb(XReg::X5, 32, XReg::X1);
            ],
            0x1000 => DATA_LB,
            {
                XReg::X1 = 0x1000 - 32;
            },
            {
                XReg::X5 = 0xFFFF_FFFF;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_lb_11() {
        isa_test!(
            0x0000 => text![
                lb(XReg::X5, 7, XReg::X1);
            ],
            0x1000 => DATA_LB,
            {
                XReg::X1 = 0x1000 - 6;
            },
            {
                XReg::X5 = 0x0000_0000;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests for Load Half Word (`lh`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lh.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LH: Vec<u8> = data![dh!(0x00FF); dh!(0xFF00); dh!(0x0FF0); dh!(0xF00F);];
    }

    // Basic Tests
    test_ld_op!(test_lh_2, lh, 0x0000_00FF, 0, 0x1000, DATA_LH);
    test_ld_op!(test_lh_3, lh, 0xFFFF_FF00, 2, 0x1000, DATA_LH);
    test_ld_op!(test_lh_4, lh, 0x0000_0FF0, 4, 0x1000, DATA_LH);
    test_ld_op!(test_lh_5, lh, 0xFFFF_F00F, 6, 0x1000, DATA_LH);

    // Test negative offset test
    test_ld_op!(test_lh_6, lh, 0x0000_00FF, -6, 0x1006, DATA_LH);
    test_ld_op!(test_lh_7, lh, 0xFFFF_FF00, -4, 0x1006, DATA_LH);
    test_ld_op!(test_lh_8, lh, 0x0000_0FF0, -2, 0x1006, DATA_LH);
    test_ld_op!(test_lh_9, lh, 0xFFFF_F00F, -0, 0x1006, DATA_LH);

    // Test with negative base
    #[test]
    fn test_lh_10() {
        isa_test!(
            0x0000 => text![
                lh(XReg::X5, 32, XReg::X1);
            ],
            0x1000 => DATA_LH,
            {
                XReg::X1 = 0x1000 - 32;
            },
            {
                XReg::X5 = 0x0000_00FF;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_lh_11() {
        isa_test!(
            0x0000 => text![
                lh(XReg::X5, 7, XReg::X1);
            ],
            0x1000 => DATA_LH,
            {
                XReg::X1 = 0x1000 - 5;
            },
            {
                XReg::X5 = 0xFFFF_FF00;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests for Load Word (`lw`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lw.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LW: Vec<u8> =
            data![dw!(0x00FF_00FF); dw!(0xFF00_FF00); dw!(0x0FF0_0FF0); dw!(0xF00F_F00F);];
    }

    // Basic Tests
    test_ld_op!(test_lw_2, lw, 0x00FF_00FF, 00, 0x1000, DATA_LW);
    test_ld_op!(test_lw_3, lw, 0xFF00_FF00, 04, 0x1000, DATA_LW);
    test_ld_op!(test_lw_4, lw, 0x0FF0_0FF0, 08, 0x1000, DATA_LW);
    test_ld_op!(test_lw_5, lw, 0xF00F_F00F, 12, 0x1000, DATA_LW);

    // Tests with negative offset
    test_ld_op!(test_lw_6, lw, 0x00FF_00FF, -12, 0x100C, DATA_LW);
    test_ld_op!(test_lw_7, lw, 0xFF00_FF00, -08, 0x100C, DATA_LW);
    test_ld_op!(test_lw_8, lw, 0x0FF0_0FF0, -04, 0x100C, DATA_LW);
    test_ld_op!(test_lw_9, lw, 0xF00F_F00F, -00, 0x100C, DATA_LW);

    // Test with negative base
    #[test]
    fn test_lw_10() {
        isa_test!(
            0x0000 => text![
                lw(XReg::X5, 32, XReg::X1);
            ],
            0x1000 => DATA_LW,
            {
                XReg::X1 = 0x1000 - 32;
            },
            {
                XReg::X5 = 0x00FF_00FF;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_lw_11() {
        isa_test!(
            0x0000 => text![
                lw(XReg::X5, 7, XReg::X1);
            ],
            0x1000 => DATA_LW,
            {
                XReg::X1 = 0x1000 - 3;
            },
            {
                XReg::X5 = 0xFF00_FF00;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests for Load Byte Unsigned(`lbu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lbu.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LBU: Vec<u8> = data![db!(0xFF); db!(0x00); db!(0xF0); db!(0x0F);];
    }

    // Basic Tests
    test_ld_op!(test_lbu_2, lbu, 0x0000_00FF, 0, 0x1000, DATA_LBU);
    test_ld_op!(test_lbu_3, lbu, 0x0000_0000, 1, 0x1000, DATA_LBU);
    test_ld_op!(test_lbu_4, lbu, 0x0000_00F0, 2, 0x1000, DATA_LBU);
    test_ld_op!(test_lbu_5, lbu, 0x0000_000F, 3, 0x1000, DATA_LBU);

    // Tests with negative offset
    test_ld_op!(test_lbu_6, lbu, 0x0000_00FF, -3, 0x1003, DATA_LBU);
    test_ld_op!(test_lbu_7, lbu, 0x0000_0000, -2, 0x1003, DATA_LBU);
    test_ld_op!(test_lbu_8, lbu, 0x0000_00F0, -1, 0x1003, DATA_LBU);
    test_ld_op!(test_lbu_9, lbu, 0x0000_000F, -0, 0x1003, DATA_LBU);

    // Test with negative base
    #[test]
    fn test_lbu_10() {
        isa_test!(
            0x0000 => text![
                lbu(XReg::X5, 32, XReg::X1);
            ],
            0x1000 => DATA_LBU,
            {
                XReg::X1 = 0x1000 - 32;
            },
            {
                XReg::X5 = 0x0000_00FF;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_lbu_11() {
        isa_test!(
            0x0000 => text![
                lbu(XReg::X5, 7, XReg::X1);
            ],
            0x1000 => DATA_LBU,
            {
                XReg::X1 = 0x1000 - 6;
            },
            {
                XReg::X5 = 0x0000_0000;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests for Load Half Word Unsigned (`lhu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/lhu.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LHU: Vec<u8> = data![dh!(0x00FF); dh!(0xFF00); dh!(0x0FF0); dh!(0xF00F);];
    }

    // Basic Tests
    test_ld_op!(test_lhu_2, lhu, 0x0000_00FF, 0, 0x1000, DATA_LHU);
    test_ld_op!(test_lhu_3, lhu, 0x0000_FF00, 2, 0x1000, DATA_LHU);
    test_ld_op!(test_lhu_4, lhu, 0x0000_0FF0, 4, 0x1000, DATA_LHU);
    test_ld_op!(test_lhu_5, lhu, 0x0000_F00F, 6, 0x1000, DATA_LHU);

    // Test negative offset test
    test_ld_op!(test_lhu_6, lhu, 0x0000_00FF, -6, 0x1006, DATA_LHU);
    test_ld_op!(test_lhu_7, lhu, 0x0000_FF00, -4, 0x1006, DATA_LHU);
    test_ld_op!(test_lhu_8, lhu, 0x0000_0FF0, -2, 0x1006, DATA_LHU);
    test_ld_op!(test_lhu_9, lhu, 0x0000_F00F, -0, 0x1006, DATA_LHU);

    // Test with negative base
    #[test]
    fn test_lhu_10() {
        isa_test!(
            0x0000 => text![
                lhu(XReg::X5, 32, XReg::X1);
            ],
            0x1000 => DATA_LHU,
            {
                XReg::X1 = 0x1000 - 32;
            },
            {
                XReg::X5 = 0x0000_00FF;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_lhu_11() {
        isa_test!(
            0x0000 => text![
                lhu(XReg::X5, 7, XReg::X1);
            ],
            0x1000 => DATA_LHU,
            {
                XReg::X1 = 0x1000 - 5;
            },
            {
                XReg::X5 = 0x0000_FF00;
            }
        );
    }
}
