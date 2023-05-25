/*++

Licensed under the Apache-2.0 license.

File Name:

    compression.rs

Abstract:

    File contains code related to compressed RISC-V instructions.

--*/
use crate::{
    types::{
        RvInstr32B, RvInstr32BranchFunct3, RvInstr32I, RvInstr32J, RvInstr32LoadFunct3,
        RvInstr32OpFunct10, RvInstr32OpImmFunct3, RvInstr32OpImmFunct7, RvInstr32Opcode,
        RvInstr32R, RvInstr32S, RvInstr32StoreFunct3, RvInstr32U,
    },
    xreg_file::XReg,
};
use caliptra_emu_types::RvException;

const OP_MASK_5: u16 = 0xe003;
const OP_MASK_6: u16 = 0xf003;
const OP_MASK_7: u16 = 0xec03;
const OP_MASK_9: u16 = 0xfc63;

macro_rules! static_assert {
    ($expression:expr) => {
        const _: () = assert!($expression);
    };
}

/// Decodes a 16-bit RV32IMC compressed instruction `instr` into a 32-bit RV32IM instruction.
///
/// # Errors
///
/// Returns error with [`RvExceptionCause::IllegalInstr`] if the instruction could be not be decoded.
pub fn decompress_instr(instr: u16) -> Result<u32, RvException> {
    match instr & OP_MASK_5 {
        rv16::CJ::OP_CODE => {
            static_assert!(rv16::CJ::OP_MASK == OP_MASK_5);
            let instr = rv16::CJ(instr);
            let mut result = RvInstr32J(0);
            result.set_opcode(RvInstr32Opcode::Jal);
            result.set_imm(i32::from(instr.imm()) as u32);
            result.set_rd(XReg::X0);
            return Ok(result.0);
        }
        rv16::CJal::OP_CODE => {
            static_assert!(rv16::CJal::OP_MASK == OP_MASK_5);
            let instr = rv16::CJal(instr);
            let mut result = RvInstr32J(0);
            result.set_opcode(RvInstr32Opcode::Jal);
            result.set_imm(i32::from(instr.imm()) as u32);
            result.set_rd(XReg::X1);
            return Ok(result.0);
        }
        rv16::CLw::OP_CODE => {
            static_assert!(rv16::CLw::OP_MASK == OP_MASK_5);
            let instr = rv16::CLw(instr);
            let mut result = RvInstr32I(0);
            result.set_opcode(RvInstr32Opcode::Load);
            result.set_funct3(RvInstr32LoadFunct3::Lw.into());
            result.set_imm(instr.uimm().into());
            result.set_rs(instr.rs1());
            result.set_rd(instr.rd());
            return Ok(result.0);
        }
        rv16::CSw::OP_CODE => {
            static_assert!(rv16::CSw::OP_MASK == OP_MASK_5);
            let instr = rv16::CSw(instr);
            let mut result = RvInstr32S(0);
            result.set_opcode(RvInstr32Opcode::Store);
            result.set_funct3(RvInstr32StoreFunct3::Sw.into());
            result.set_imm(instr.uimm().into());
            result.set_rs1(instr.rs1());
            result.set_rs2(instr.rs2());
            return Ok(result.0);
        }
        rv16::CLwsp::OP_CODE => {
            static_assert!(rv16::CLwsp::OP_MASK == OP_MASK_5);
            let instr = rv16::CLwsp(instr);
            if instr.rd() != XReg::X0 {
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::Load);
                result.set_funct3(RvInstr32LoadFunct3::Lw.into());
                result.set_uimm(instr.uimm().into());
                result.set_rs(XReg::X2);
                result.set_rd(instr.rd());
                return Ok(result.0);
            }
        }
        rv16::CSwsp::OP_CODE => {
            static_assert!(rv16::CSwsp::OP_MASK == OP_MASK_5);
            let instr = rv16::CSwsp(instr);
            let mut result = RvInstr32S(0);
            result.set_opcode(RvInstr32Opcode::Store);
            result.set_funct3(RvInstr32StoreFunct3::Sw.into());
            result.set_imm(instr.uimm().into());
            result.set_rs1(XReg::X2);
            result.set_rs2(instr.rs2());
            return Ok(result.0);
        }
        rv16::CAddi::OP_CODE => {
            static_assert!(rv16::CAddi::OP_MASK == OP_MASK_5);
            let instr = rv16::CAddi(instr);
            let mut result = RvInstr32I(0);
            result.set_opcode(RvInstr32Opcode::OpImm);
            result.set_funct3(RvInstr32OpImmFunct3::Addi.into());
            result.set_imm(instr.nzimm().into());
            result.set_rs(instr.rs1rd());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        rv16::CAddi4spn::OP_CODE => {
            static_assert!(rv16::CAddi4spn::OP_MASK == OP_MASK_5);
            let instr = rv16::CAddi4spn(instr);
            if instr.nzuimm() != 0 {
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::OpImm);
                result.set_funct3(RvInstr32OpImmFunct3::Addi.into());
                result.set_imm(instr.nzuimm().into());
                result.set_rs(XReg::X2);
                result.set_rd(instr.rd());
                return Ok(result.0);
            }
        }
        rv16::CLi::OP_CODE => {
            static_assert!(rv16::CLui::OP_MASK == OP_MASK_5);
            let instr = rv16::CLi(instr);
            let mut result = RvInstr32I(0);
            result.set_opcode(RvInstr32Opcode::OpImm);
            result.set_funct3(RvInstr32OpImmFunct3::Addi.into());
            result.set_imm(instr.nzimm());
            result.set_rs(XReg::X0);
            result.set_rd(instr.rd());
            return Ok(result.0);
        }
        rv16::CLui::OP_CODE => {
            static_assert!(rv16::CLui::OP_MASK == OP_MASK_5);
            let instr = rv16::CLui(instr);
            if instr.nzimm() != 0 {
                if instr.rd() == XReg::X2 {
                    static_assert!(rv16::CAddi16sp::OP_MASK == OP_MASK_5);
                    static_assert!(rv16::CAddi16sp::OP_CODE == rv16::CLui::OP_CODE);
                    let instr = rv16::CAddi16sp(instr.0);
                    let mut result = RvInstr32I(0);
                    result.set_opcode(RvInstr32Opcode::OpImm);
                    result.set_funct3(RvInstr32OpImmFunct3::Addi.into());
                    result.set_imm(instr.nzimm());
                    result.set_rs(XReg::X2);
                    result.set_rd(XReg::X2);
                    return Ok(result.0);
                } else {
                    let mut result = RvInstr32U(0);
                    result.set_opcode(RvInstr32Opcode::Lui);
                    result.set_imm(instr.nzimm() >> 12);
                    result.set_rd(instr.rd());
                    return Ok(result.0);
                }
            }
        }
        rv16::CBeqz::OP_CODE => {
            static_assert!(rv16::CBeqz::OP_MASK == OP_MASK_5);
            let instr = rv16::CBeqz(instr);
            let mut result = RvInstr32B(0);
            result.set_opcode(RvInstr32Opcode::Branch);
            result.set_funct3(RvInstr32BranchFunct3::Beq.into());
            result.set_imm(i32::from(instr.offset()) as u32);
            result.set_rs1(instr.rs1());
            result.set_rs2(XReg::X0);
            return Ok(result.0);
        }
        rv16::CBnez::OP_CODE => {
            static_assert!(rv16::CBnez::OP_MASK == OP_MASK_5);
            let instr = rv16::CBnez(instr);
            let mut result = RvInstr32B(0);
            result.set_opcode(RvInstr32Opcode::Branch);
            result.set_funct3(RvInstr32BranchFunct3::Bne.into());
            result.set_imm(i32::from(instr.offset()) as u32);
            result.set_rs1(instr.rs1());
            result.set_rs2(XReg::X0);
            return Ok(result.0);
        }
        rv16::CSlli::OP_CODE => {
            static_assert!(rv16::CSlli::OP_MASK == OP_MASK_5);
            let instr = rv16::CSlli(instr);
            let mut result = RvInstr32I(0);
            // For RV32C, code points with shamt[5] == 1 are reserved
            if instr.shamt() & 0x20 == 0 {
                result.set_opcode(RvInstr32Opcode::OpImm);
                result.set_funct3(RvInstr32OpImmFunct3::Sli.into());
                result.set_uimm(instr.shamt().into());
                result.set_rs(instr.rs1rd());
                result.set_rd(instr.rs1rd());
                return Ok(result.0);
            }
        }
        _ => {}
    }

    match instr & OP_MASK_6 {
        rv16::CMv::OP_CODE => {
            static_assert!(rv16::CMv::OP_MASK == OP_MASK_6);
            let instr = rv16::CMv(instr);
            if instr.rs2() == XReg::X0 {
                let instr = rv16::CJr(instr.0);
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::Jalr);
                result.set_funct3(0);
                result.set_imm(0);
                result.set_rs(instr.rs1());
                result.set_rd(XReg::X0);
                return Ok(result.0);
            } else {
                let mut result = RvInstr32R(0);
                result.set_opcode(RvInstr32Opcode::Op);
                result.set_funct10(RvInstr32OpFunct10::Add);
                result.set_rs1(XReg::X0);
                result.set_rs2(instr.rs2());
                result.set_rd(instr.rd());
                return Ok(result.0);
            }
        }
        rv16::CAdd::OP_CODE => {
            static_assert!(rv16::CAdd::OP_MASK == OP_MASK_6);
            let instr = rv16::CAdd(instr);
            if instr.rs1rd() == XReg::X0 && instr.rs2() == XReg::X0 {
                // EBREAK
                return Ok(0x100073);
            }
            if instr.rs2() == XReg::X0 {
                let instr = rv16::CJalr(instr.0);
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::Jalr);
                result.set_funct3(0);
                result.set_imm(0);
                result.set_rs(instr.rs1());
                result.set_rd(XReg::X1);
                return Ok(result.0);
            } else {
                let mut result = RvInstr32R(0);
                result.set_opcode(RvInstr32Opcode::Op);
                result.set_funct10(RvInstr32OpFunct10::Add);
                result.set_rs1(instr.rs1rd());
                result.set_rs2(instr.rs2());
                result.set_rd(instr.rs1rd());
                return Ok(result.0);
            }
        }
        _ => {}
    }

    match instr & OP_MASK_7 {
        rv16::CSrli::OP_CODE => {
            static_assert!(rv16::CSrli::OP_MASK == OP_MASK_7);
            let instr = rv16::CSrli(instr);

            // For RV32C, code points with shamt[5] == 1 are reserved
            if instr.shamt() & 0x20 == 0 {
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::OpImm);
                result.set_funct7(RvInstr32OpImmFunct7::Srli.into());
                result.set_funct3(RvInstr32OpImmFunct3::Sri.into());
                result.set_shamt(instr.shamt());
                result.set_rs(instr.rs1rd());
                result.set_rd(instr.rs1rd());
                return Ok(result.0);
            }
        }
        rv16::CSrai::OP_CODE => {
            static_assert!(rv16::CSrai::OP_MASK == OP_MASK_7);
            let instr = rv16::CSrai(instr);

            // For RV32C, code points with shamt[5] == 1 are reserved
            if instr.shamt() & 0x20 == 0 {
                let mut result = RvInstr32I(0);
                result.set_opcode(RvInstr32Opcode::OpImm);
                result.set_funct7(RvInstr32OpImmFunct7::Srai.into());
                result.set_funct3(RvInstr32OpImmFunct3::Sri.into());
                result.set_shamt(instr.shamt());
                result.set_rs(instr.rs1rd());
                result.set_rd(instr.rs1rd());
                return Ok(result.0);
            }
        }
        rv16::CAndi::OP_CODE => {
            static_assert!(rv16::CAndi::OP_MASK == OP_MASK_7);
            let instr = rv16::CAndi(instr);
            let mut result = RvInstr32I(0);
            result.set_opcode(RvInstr32Opcode::OpImm);
            result.set_funct3(RvInstr32OpImmFunct3::Andi.into());
            result.set_imm(instr.imm().into());
            result.set_rs(instr.rs1rd());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        _ => {}
    }

    match instr & OP_MASK_9 {
        rv16::CAnd::OP_CODE => {
            static_assert!(rv16::CAnd::OP_MASK == OP_MASK_9);
            let instr = rv16::CAnd(instr);
            let mut result = RvInstr32R(0);
            result.set_opcode(RvInstr32Opcode::Op);
            result.set_funct10(RvInstr32OpFunct10::And);
            result.set_rs1(instr.rs1rd());
            result.set_rs2(instr.rs2());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        rv16::COr::OP_CODE => {
            static_assert!(rv16::COr::OP_MASK == OP_MASK_9);
            let instr = rv16::COr(instr);
            let mut result = RvInstr32R(0);
            result.set_opcode(RvInstr32Opcode::Op);
            result.set_funct10(RvInstr32OpFunct10::Or);
            result.set_rs1(instr.rs1rd());
            result.set_rs2(instr.rs2());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        rv16::CXor::OP_CODE => {
            static_assert!(rv16::CXor::OP_MASK == OP_MASK_9);
            let instr = rv16::CXor(instr);
            let mut result = RvInstr32R(0);
            result.set_opcode(RvInstr32Opcode::Op);
            result.set_funct10(RvInstr32OpFunct10::Xor);
            result.set_rs1(instr.rs1rd());
            result.set_rs2(instr.rs2());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        rv16::CSub::OP_CODE => {
            static_assert!(rv16::CSub::OP_MASK == OP_MASK_9);
            let instr = rv16::CSub(instr);
            let mut result = RvInstr32R(0);
            result.set_opcode(RvInstr32Opcode::Op);
            result.set_funct10(RvInstr32OpFunct10::Sub);
            result.set_rs1(instr.rs1rd());
            result.set_rs2(instr.rs2());
            result.set_rd(instr.rs1rd());
            return Ok(result.0);
        }
        _ => {}
    }
    Err(RvException::illegal_instr(u32::from(instr)))
}

mod rv16 {

    use crate::xreg_file::XReg;
    use bitfield::{bitfield, BitRangeMut};

    fn bit_range(val: u16, msb: usize, lsb: usize) -> u16 {
        bitfield::BitRange::bit_range(&val, msb, lsb)
    }
    fn sign_extend(val: u16, msb: u16) -> i16 {
        let sh = 15 - msb;
        ((val << sh) as i16) >> sh
    }
    fn sign_extend_i32(val: u32, msb: u32) -> i32 {
        let sh = 31 - msb;
        ((val << sh) as i32) >> sh
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.LWSP instruction
        pub struct CLwsp(u16);

        /// Destination Register
        pub from into XReg, rd, set_rd: 11, 7;
    }
    impl CLwsp {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x4002;

        pub fn uimm(&self) -> u16 {
            let mut result = 0;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 2, bit_range(self.0, 6, 4));
            result.set_bit_range(7, 6, bit_range(self.0, 3, 2));
            result
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.SWSP instruction
        pub struct CSwsp(u16);

        /// Source Register
        pub from into XReg, rs2, set_rs2: 6, 2;
    }
    impl CSwsp {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0xc002;

        pub fn uimm(&self) -> u16 {
            let mut result = 0;
            result.set_bit_range(5, 2, bit_range(self.0, 12, 9));
            result.set_bit_range(7, 6, bit_range(self.0, 8, 7));
            result
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.LW instruction
        pub struct CLw(u16);
    }
    impl CLw {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x4000;

        pub fn rs1(&self) -> XReg {
            XReg::from(bit_range(self.0, 9, 7) + 8)
        }
        pub fn rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 4, 2) + 8)
        }

        pub fn uimm(&self) -> u16 {
            let mut result = 0;
            result.set_bit_range(5, 3, bit_range(self.0, 12, 10));
            result.set_bit_range(2, 2, bit_range(self.0, 6, 6));
            result.set_bit_range(6, 6, bit_range(self.0, 5, 5));
            result
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.SW instruction
        pub struct CSw(u16);
    }
    impl CSw {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0xc000;

        pub fn rs1(&self) -> XReg {
            XReg::from(bit_range(self.0, 9, 7) + 8)
        }
        pub fn rs2(&self) -> XReg {
            XReg::from(bit_range(self.0, 4, 2) + 8)
        }

        pub fn uimm(&self) -> u16 {
            let mut result = 0;
            result.set_bit_range(5, 3, bit_range(self.0, 12, 10));
            result.set_bit_range(2, 2, bit_range(self.0, 6, 6));
            result.set_bit_range(6, 6, bit_range(self.0, 5, 5));
            result
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.J instruction
        pub struct CJ(u16);
    }
    impl CJ {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0xa001;

        pub fn imm(&self) -> i16 {
            let mut result = 0u16;
            result.set_bit_range(11, 11, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 4, bit_range(self.0, 11, 11));
            result.set_bit_range(9, 8, bit_range(self.0, 10, 9));
            result.set_bit_range(10, 10, bit_range(self.0, 8, 8));
            result.set_bit_range(6, 6, bit_range(self.0, 7, 7));
            result.set_bit_range(7, 7, bit_range(self.0, 6, 6));
            result.set_bit_range(3, 1, bit_range(self.0, 5, 3));
            result.set_bit_range(5, 5, bit_range(self.0, 2, 2));
            sign_extend(result, 11)
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.JAL instruction
        pub struct CJal(u16);
    }
    impl CJal {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x2001;

        pub fn imm(&self) -> i16 {
            CJ(self.0).imm()
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.ADDI instruction
        pub struct CAddi(u16);
    }
    impl CAddi {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x0001;

        pub fn nzimm(&self) -> i16 {
            let mut result = 0u16;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            sign_extend(result, 5)
        }
        pub fn rs1rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 11, 7))
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.ADDI4SPN instruction
        pub struct CAddi4spn(u16);
    }
    impl CAddi4spn {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x0000;

        pub fn nzuimm(&self) -> u16 {
            let mut result = 0u16;
            result.set_bit_range(5, 4, bit_range(self.0, 12, 11));
            result.set_bit_range(9, 6, bit_range(self.0, 10, 7));
            result.set_bit_range(2, 2, bit_range(self.0, 6, 6));
            result.set_bit_range(3, 3, bit_range(self.0, 5, 5));
            result
        }

        pub fn rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 4, 2) + 8)
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.ADDI16SP instruction
        pub struct CAddi16sp(u16);
    }
    impl CAddi16sp {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        #[allow(dead_code)]
        pub const OP_CODE: u16 = 0x6001;

        pub fn nzimm(&self) -> i32 {
            let mut result = 0u32;
            result.set_bit_range(9, 9, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 4, bit_range(self.0, 6, 6));
            result.set_bit_range(6, 6, bit_range(self.0, 5, 5));
            result.set_bit_range(8, 7, bit_range(self.0, 4, 3));
            result.set_bit_range(5, 5, bit_range(self.0, 2, 2));
            sign_extend_i32(result, 9)
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.LI instruction
        pub struct CLi(u16);
    }
    impl CLi {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x4001;

        pub fn nzimm(&self) -> i32 {
            let mut result = 0u32;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            sign_extend_i32(result, 5)
        }

        pub fn rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 11, 7))
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.LUI instruction
        pub struct CLui(u16);
    }
    impl CLui {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x6001;

        pub fn nzimm(&self) -> i32 {
            let mut d = 0u32;
            d.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            d.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            let mut result = 0u32;
            result.set_bit_range(17, 17, bit_range(self.0, 12, 12));
            result.set_bit_range(16, 12, bit_range(self.0, 6, 2));
            sign_extend_i32(result, 17)
        }

        pub fn rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 11, 7))
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.BEQZ instruction
        pub struct CBeqz(u16);
    }
    impl CBeqz {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0xc001;

        pub fn offset(&self) -> i16 {
            let mut result = 0u16;
            result.set_bit_range(8, 8, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 3, bit_range(self.0, 11, 10));
            result.set_bit_range(7, 6, bit_range(self.0, 6, 5));
            result.set_bit_range(2, 1, bit_range(self.0, 4, 3));
            result.set_bit_range(5, 5, bit_range(self.0, 2, 2));
            sign_extend(result, 8)
        }

        pub fn rs1(&self) -> XReg {
            XReg::from(bit_range(self.0, 9, 7) + 8)
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.BNEZ instruction
        pub struct CBnez(u16);
    }
    impl CBnez {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0xe001;

        pub fn offset(&self) -> i16 {
            CBeqz(self.0).offset()
        }
        pub fn rs1(&self) -> XReg {
            CBeqz(self.0).rs1()
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.BNEZ instruction
        pub struct CSlli(u16);
    }
    impl CSlli {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xe003;
        pub const OP_CODE: u16 = 0x0002;

        pub fn shamt(&self) -> u16 {
            let mut result = 0u16;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            result
        }
        pub fn rs1rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 11, 7))
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.MV instruction
        pub struct CMv(u16);

        pub from into XReg, rd, set_rd: 11, 7;
        pub from into XReg, rs2, set_rs2: 6, 2;
    }
    impl CMv {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xf003;
        pub const OP_CODE: u16 = 0x8002;
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.ADD instruction
        pub struct CAdd(u16);

        pub from into XReg, rs1rd, set_rs1rd: 11, 7;
        pub from into XReg, rs2, set_rs2: 6, 2;
    }
    impl CAdd {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xf003;
        pub const OP_CODE: u16 = 0x9002;
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.JALR instruction
        pub struct CJalr(u16);

        pub from into XReg, rs1, set_rs1: 11, 7;
        pub from into XReg, rs2, set_rs2: 6, 2;
    }
    impl CJalr {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xf07f;
        #[allow(dead_code)]
        pub const OP_CODE: u16 = 0x9002;
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.JR instruction
        pub struct CJr(u16);

        pub from into XReg, rs1, set_rs1: 11, 7;
        pub from into XReg, rs2, set_rs2: 6, 2;
    }
    impl CJr {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xf07f;
        #[allow(dead_code)]
        pub const OP_CODE: u16 = 0x8002;
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.SRLI instruction
        pub struct CSrli(u16);
    }
    impl CSrli {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xec03;
        pub const OP_CODE: u16 = 0x8001;

        pub fn shamt(&self) -> u32 {
            let mut result = 0;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            result
        }
        pub fn rs1rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 9, 7) + 8)
        }
    }
    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.SRAI instruction
        pub struct CSrai(u16);
    }
    impl CSrai {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xec03;
        pub const OP_CODE: u16 = 0x8401;

        pub fn shamt(&self) -> u32 {
            CSrli(self.0).shamt()
        }
        pub fn rs1rd(&self) -> XReg {
            CSrli(self.0).rs1rd()
        }
    }
    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.ANDI instruction
        pub struct CAndi(u16);
    }
    impl CAndi {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xec03;
        pub const OP_CODE: u16 = 0x8801;

        pub fn imm(&self) -> i16 {
            let mut result = 0;
            result.set_bit_range(5, 5, bit_range(self.0, 12, 12));
            result.set_bit_range(4, 0, bit_range(self.0, 6, 2));
            sign_extend(result, 5)
        }
        pub fn rs1rd(&self) -> XReg {
            CSrli(self.0).rs1rd()
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.AND instruction
        pub struct CAnd(u16);
    }
    impl CAnd {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xfc63;
        pub const OP_CODE: u16 = 0x8c61;

        pub fn rs1rd(&self) -> XReg {
            XReg::from(bit_range(self.0, 9, 7) + 8)
        }
        pub fn rs2(&self) -> XReg {
            XReg::from(bit_range(self.0, 4, 2) + 8)
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.OR instruction
        pub struct COr(u16);
    }
    impl COr {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xfc63;
        pub const OP_CODE: u16 = 0x8c41;

        pub fn rs1rd(&self) -> XReg {
            CAnd(self.0).rs1rd()
        }
        pub fn rs2(&self) -> XReg {
            CAnd(self.0).rs2()
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.XOR instruction
        pub struct CXor(u16);
    }
    impl CXor {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xfc63;
        pub const OP_CODE: u16 = 0x8c21;

        pub fn rs1rd(&self) -> XReg {
            CAnd(self.0).rs1rd()
        }
        pub fn rs2(&self) -> XReg {
            CAnd(self.0).rs2()
        }
    }

    bitfield! {
        #[derive(Debug, PartialEq, Eq, Clone, Copy)]
        /// RISCV C.SUB instruction
        pub struct CSub(u16);
    }
    impl CSub {
        #[allow(dead_code)]
        pub const OP_MASK: u16 = 0xfc63;
        pub const OP_CODE: u16 = 0x8c01;

        pub fn rs1rd(&self) -> XReg {
            CAnd(self.0).rs1rd()
        }
        pub fn rs2(&self) -> XReg {
            CAnd(self.0).rs2()
        }
    }
}
