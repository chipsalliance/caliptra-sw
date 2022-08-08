/*++

Licensed under the Apache-2.0 license.

File Name:

    store.rs

Abstract:

    File contains implementation of RISCV Store Instructions

--*/

use crate::cpu::{Cpu, InstrTracer};
use crate::trace_instr;
use crate::types::{RvInstr, RvInstr32Opcode, RvInstr32S, RvInstr32StoreFunct3};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvException, RvSize};

impl<TBus: Bus> Cpu<TBus> {
    /// Execute store instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_store_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32S(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Store);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::SType(instr));

        // Calculate the address to load the data from
        let addr = (self.read_xreg(instr.rs1())? as RvAddr).wrapping_add(instr.imm() as RvAddr);
        let val = self.read_xreg(instr.rs2())?;

        match instr.funct3().into() {
            // Store Byte ('sb') Instruction
            RvInstr32StoreFunct3::Sb => self.bus.write(RvSize::Byte, addr, val),

            // Store Half Word ('sh') Instruction
            RvInstr32StoreFunct3::Sh => self.bus.write(RvSize::HalfWord, addr, val),

            // Store Word ('sw') Instruction
            RvInstr32StoreFunct3::Sw => self.bus.write(RvSize::Word, addr, val),

            // Illegal Instruction
            _ => Err(RvException::illegal_instr(instr.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{addi, lb, lh, lw, sb, sh, sw};
    use crate::xreg_file::XReg;
    use crate::{data, db, dh, dw, isa_test, test_st_op, text};
    use lazy_static::lazy_static;

    // ---------------------------------------------------------------------------------------------
    // Tests For Store Byte (`sb`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sb.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LB: Vec<u8> = data![
            db!(0xEF); db!(0xEF); db!(0xEF); db!(0xEF); db!(0xEF);
            db!(0xEF); db!(0xEF); db!(0xEF); db!(0xEF); db!(0xEF);
        ];
    }

    // Basic Tests
    test_st_op!(test_sb_2, lb, sb, 0xFFFF_FFAA, 0, 0x1000, DATA_LB);
    test_st_op!(test_sb_3, lb, sb, 0x0000_0000, 1, 0x1000, DATA_LB);
    test_st_op!(test_sb_4, lh, sb, 0xFFFF_EFA0, 2, 0x1000, DATA_LB);
    test_st_op!(test_sb_5, lb, sb, 0x0000_000A, 3, 0x1000, DATA_LB);

    // Test with negative offset
    test_st_op!(test_sb_6, lb, sb, 0xFFFF_FFAA, -3, 0x1003, DATA_LB);
    test_st_op!(test_sb_7, lb, sb, 0x0000_0000, -2, 0x1003, DATA_LB);
    test_st_op!(test_sb_8, lb, sb, 0xFFFF_FFA0, -1, 0x1003, DATA_LB);
    test_st_op!(test_sb_9, lb, sb, 0x0000_000A, -0, 0x1003, DATA_LB);

    // Test with negative base
    #[test]
    fn test_sb_10() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X4, XReg::X1, -32);
                sb(XReg::X2, 32, XReg::X4);
                lb(XReg::X5, 0, XReg::X1);
            ],
            0x1000 => DATA_LB,
            {
                XReg::X1 = 0x0000_1000;
                XReg::X2 = 0x1234_5678;
            },
            {
                XReg::X5 = 0x0000_0078;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_sb_11() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X1, XReg::X1, -6);
                sb(XReg::X2, 7, XReg::X1);
                lb(XReg::X5, 0, XReg::X4);
            ],
            0x1000 => DATA_LB,
            {
                XReg::X1 = 0x0000_1008;
                XReg::X2 = 0x0000_3098;
                XReg::X4 = 0x0000_1009;
            },
            {
                XReg::X5 = 0xFFFF_FF98;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests For Store HalF Word (`sh`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sh.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LH: Vec<u8> = data![
            dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF);
            dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF); dh!(0xBEEF);
        ];
    }

    // Basic Tests
    test_st_op!(test_sh_2, lh, sh, 0x000000AA, 0, 0x1000, DATA_LH);
    test_st_op!(test_sh_3, lh, sh, 0xFFFFAA00, 2, 0x1000, DATA_LH);
    test_st_op!(test_sh_4, lw, sh, 0xBEEF0AA0, 4, 0x1000, DATA_LH);
    test_st_op!(test_sh_5, lh, sh, 0xFFFFA00A, 6, 0x1000, DATA_LH);

    // Test with negative offset
    test_st_op!(test_sh_6, lh, sh, 0x000000AA, -6, 0x1010, DATA_LH);
    test_st_op!(test_sh_7, lh, sh, 0xFFFFAA00, -4, 0x1010, DATA_LH);
    test_st_op!(test_sh_8, lh, sh, 0x00000AA0, -2, 0x1010, DATA_LH);
    test_st_op!(test_sh_9, lh, sh, 0xFFFFA00A, -0, 0x1010, DATA_LH);

    // Test with negative base
    #[test]
    fn test_sh_10() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X4, XReg::X1, -32);
                sh(XReg::X2, 32, XReg::X4);
                lh(XReg::X5, 0, XReg::X1);
            ],
            0x1000 => DATA_LH,
            {
                XReg::X1 = 0x0000_1000;
                XReg::X2 = 0x1234_5678;
            },
            {
                XReg::X5 = 0x0000_5678;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_sh_11() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X1, XReg::X1, -5);
                sh(XReg::X2, 7, XReg::X1);
                lh(XReg::X5, 0, XReg::X4);
            ],
            0x1000 => DATA_LH,
            {
                XReg::X1 = 0x0000_1010;
                XReg::X2 = 0x0000_3098;
                XReg::X4 = 0x0000_1012;
            },
            {
                XReg::X5 = 0x0000_3098;
            }
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Tests For Store  Word (`sw`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64ui/sw.S
    // ---------------------------------------------------------------------------------------------

    lazy_static! {
        static ref DATA_LW: Vec<u8> = data![
            dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF);
            dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF); dw!(0xDEAD_BEEF);
        ];
    }

    // Basic Tests
    test_st_op!(test_sw_2, lw, sw, 0x00AA_00AA, 00, 0x1000, DATA_LW);
    test_st_op!(test_sw_3, lw, sw, 0xAA00_AA00, 04, 0x1000, DATA_LW);
    test_st_op!(test_sw_4, lw, sw, 0x0AA0_0AA0, 08, 0x1000, DATA_LW);
    test_st_op!(test_sw_5, lw, sw, 0xA00A_A00a, 12, 0x1000, DATA_LW);

    // Test with negative offset
    test_st_op!(test_sw_6, lw, sw, 0x00AA_00AA, -12, 0x1010, DATA_LW);
    test_st_op!(test_sw_7, lw, sw, 0xAA00_AA00, -08, 0x1010, DATA_LW);
    test_st_op!(test_sw_8, lw, sw, 0x0AA0_0AA0, -04, 0x1010, DATA_LW);
    test_st_op!(test_sw_9, lw, sw, 0xA00A_A00A, -00, 0x1010, DATA_LW);

    // Test with negative base
    #[test]
    fn test_sw_10() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X4, XReg::X1, -32);
                sw(XReg::X2, 32, XReg::X4);
                lw(XReg::X5, 0, XReg::X1);
            ],
            0x1000 => DATA_LW,
            {
                XReg::X1 = 0x0000_1010;
                XReg::X2 = 0x1234_5678;
            },
            {
                XReg::X5 = 0x1234_5678;
            }
        );
    }

    // Test with unaligned base
    #[test]
    fn test_sw_11() {
        isa_test!(
            0x0000 => text![
                addi(XReg::X1, XReg::X1, -3);
                sw(XReg::X2, 7, XReg::X1);
                lw(XReg::X5, 0, XReg::X4);
            ],
            0x1000 => DATA_LW,
            {
                XReg::X1 = 0x0000_1010;
                XReg::X2 = 0x5821_3098;
                XReg::X4 = 0x0000_1014;
            },
            {
                XReg::X5 = 0x5821_3098;
            }
        );
    }
}
