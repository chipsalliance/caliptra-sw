/*++

Licensed under the Apache-2.0 license.

File Name:

    test_encoder.rs

Abstract:

    File contains implementation of RISCV Instruction encoding.

--*/

#[cfg(test)]
pub mod tests {
    use crate::types::{
        RvInstr32B, RvInstr32BranchFunct3, RvInstr32I, RvInstr32J, RvInstr32LoadFunct3,
        RvInstr32OpFunct3, RvInstr32OpFunct7, RvInstr32OpImmFunct3, RvInstr32OpImmFunct7,
        RvInstr32Opcode, RvInstr32R, RvInstr32S, RvInstr32StoreFunct3, RvInstr32SystemFunct3,
        RvInstr32SystemImm, RvInstr32U,
    };
    use crate::xreg_file::XReg;

    macro_rules! ld_instr {
        ($name:ident, $funct3:ident) => {
            /// Encode load instruction
            pub fn $name(rd: XReg, imm: i32, rs: XReg) -> u32 {
                let mut instr = RvInstr32I(0);
                instr.set_opcode(RvInstr32Opcode::Load);
                instr.set_rd(rd);
                instr.set_funct3(RvInstr32LoadFunct3::$funct3.into());
                instr.set_rs(rs);
                instr.set_imm(imm);
                instr.0
            }
        };
    }

    macro_rules! op_imm_instr {
        ($name:ident, $funct3:ident) => {
            /// Encode immediate instruction
            pub fn $name(rd: XReg, rs: XReg, imm: i32) -> u32 {
                let mut instr = RvInstr32I(0);
                instr.set_opcode(RvInstr32Opcode::OpImm);
                instr.set_rd(rd);
                instr.set_funct3(RvInstr32OpImmFunct3::$funct3.into());
                instr.set_rs(rs);
                instr.set_imm(imm);
                instr.0
            }
        };

        ($name:ident, $funct3:ident, $funct7:ident) => {
            /// Encode immediate instruction
            pub fn $name(rd: XReg, rs: XReg, shamt: u32) -> u32 {
                let mut instr = RvInstr32I(0);
                instr.set_opcode(RvInstr32Opcode::OpImm);
                instr.set_rd(rd);
                instr.set_funct3(RvInstr32OpImmFunct3::$funct3.into());
                instr.set_rs(rs);
                instr.set_shamt(shamt);
                instr.set_funct7(RvInstr32OpImmFunct7::$funct7.into());
                instr.0
            }
        };
    }

    macro_rules! st_instr {
        ($name:ident, $funct3:ident) => {
            /// Encode store instruction
            pub fn $name(rs2: XReg, imm: i32, rs1: XReg) -> u32 {
                let mut instr = RvInstr32S(0);
                instr.set_opcode(RvInstr32Opcode::Store);
                instr.set_rs2(rs2);
                instr.set_funct3(RvInstr32StoreFunct3::$funct3.into());
                instr.set_rs1(rs1);
                instr.set_imm(imm);
                instr.0
            }
        };
    }

    macro_rules! op_instr {
        ($name:ident, $funct3:ident, $funct7:ident) => {
            /// Encode register op instruction
            pub fn $name(rd: XReg, rs1: XReg, rs2: XReg) -> u32 {
                let mut instr = RvInstr32R(0);
                instr.set_opcode(RvInstr32Opcode::Op);
                instr.set_rd(rd);
                instr.set_rs1(rs1);
                instr.set_rs2(rs2);
                instr.set_funct3(RvInstr32OpFunct3::$funct3.into());
                instr.set_funct7(RvInstr32OpFunct7::$funct7.into());
                instr.0
            }
        };
    }

    macro_rules! branch_instr {
        ($name:ident, $funct3:ident) => {
            /// Encode register op instruction
            pub fn $name(rs1: XReg, rs2: XReg, imm: u32) -> u32 {
                let mut instr = RvInstr32B(0);
                instr.set_opcode(RvInstr32Opcode::Branch);
                instr.set_funct3(RvInstr32BranchFunct3::$funct3.into());
                instr.set_rs1(rs1);
                instr.set_rs2(rs2);
                instr.set_imm(imm);
                instr.0
            }
        };
    }

    macro_rules! op_system_instr {
        ($name:ident, $funct3:ident) => {
            /// Encode immediate instruction
            pub fn $name(rd: XReg, rs: XReg, imm: u32) -> u32 {
                let mut instr = RvInstr32I(0);
                instr.set_opcode(RvInstr32Opcode::System);
                instr.set_rd(rd);
                instr.set_funct3(RvInstr32SystemFunct3::$funct3.into());
                instr.set_rs(rs);
                instr.set_uimm(imm);
                instr.0
            }
        };

        ($name:ident, $funct3:ident, $imm:ident) => {
            /// Encode immediate instruction
            pub fn $name() -> u32 {
                let mut instr = RvInstr32I(0);
                instr.set_opcode(RvInstr32Opcode::System);
                instr.set_rd(XReg::X0);
                instr.set_funct3(RvInstr32SystemFunct3::$funct3.into());
                instr.set_rs(XReg::X0);
                instr.set_uimm(RvInstr32SystemImm::$imm.into());
                instr.0
            }
        };
    }

    ld_instr!(lb, Lb);
    ld_instr!(lh, Lh);
    ld_instr!(lw, Lw);
    ld_instr!(lbu, Lbu);
    ld_instr!(lhu, Lhu);

    op_imm_instr!(addi, Addi);
    op_imm_instr!(slli, Sli, Slli);
    op_imm_instr!(slti, Slti);
    op_imm_instr!(sltiu, Sltiu);
    op_imm_instr!(xori, Xori);
    op_imm_instr!(srli, Sri, Srli);

    op_imm_instr!(srai, Sri, Srai);
    op_imm_instr!(ori, Ori);
    op_imm_instr!(andi, Andi);

    /// Encode No-op.rs instruction
    pub fn nop() -> u32 {
        addi(XReg::X0, XReg::X0, 0)
    }

    pub fn sign_extend(x: u32) -> u32 {
        let x = x as i32;
        let x = x | (-(((x) >> 11) & 1) << 11);
        x as u32
    }

    /// Encode Add Upper Immediate to program counter (`auipc`) instruction
    pub fn auipc(rd: XReg, imm: i32) -> u32 {
        let mut instr = RvInstr32U(0);
        instr.set_opcode(RvInstr32Opcode::Auipc);
        instr.set_rd(rd);
        instr.set_imm(imm);
        instr.0
    }

    st_instr!(sb, Sb);
    st_instr!(sh, Sh);
    st_instr!(sw, Sw);

    op_instr!(add, Zero, Add);
    op_instr!(mul, Zero, Mul);
    op_instr!(sub, Zero, Sub);
    op_instr!(sll, One, Sll);
    op_instr!(mulh, One, Mulh);
    op_instr!(slt, Two, Slt);
    op_instr!(mulhsu, Two, Mulhsu);
    op_instr!(sltu, Three, Sltu);
    op_instr!(mulhu, Three, Mulhu);
    op_instr!(xor, Four, Xor);
    op_instr!(div, Four, Div);
    op_instr!(srl, Five, Srl);
    op_instr!(divu, Five, Divu);
    op_instr!(sra, Five, Sra);
    op_instr!(or, Six, Or);
    op_instr!(rem, Six, Rem);
    op_instr!(and, Seven, And);
    op_instr!(remu, Seven, Remu);

    // bit manipulation extension
    op_instr!(sh1add, Two, Sh1add);
    op_instr!(sh2add, Four, Sh1add);
    op_instr!(sh3add, Six, Sh1add);
    op_instr!(bset, One, Bset);
    op_instr!(binv, One, Binv);
    op_instr!(bclr, One, Bclr);
    op_instr!(bext, Five, Bclr);
    op_instr!(andn, Seven, Sub);
    op_instr!(orn, Six, Sub);
    op_instr!(xnor, Four, Sub);
    op_instr!(max, Six, MinMaxClmul);
    op_instr!(maxu, Seven, MinMaxClmul);
    op_instr!(min, Four, MinMaxClmul);
    op_instr!(minu, Five, MinMaxClmul);
    op_instr!(rol, One, Rotate);
    op_instr!(ror, Five, Rotate);
    op_instr!(clmul, One, MinMaxClmul);
    op_instr!(clmulh, Three, MinMaxClmul);
    op_instr!(clmulr, Two, MinMaxClmul);
    op_imm_instr!(bseti, Sli, Orc);
    op_imm_instr!(binvi, Sli, Rev8);
    op_imm_instr!(bclri, Sli, Bclr);
    op_imm_instr!(bexti, Sri, Bclr);
    op_imm_instr!(rori, Sri, Bitmanip);

    pub fn clz(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x600);
        instr.set_funct3(1);
        instr.0
    }

    pub fn cpop(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x602);
        instr.set_funct3(1);
        instr.0
    }

    pub fn ctz(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x601);
        instr.set_funct3(1);
        instr.0
    }

    pub fn orc_b(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x287);
        instr.set_funct3(5);
        instr.0
    }

    pub fn rev8(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x698);
        instr.set_funct3(5);
        instr.0
    }

    pub fn sext_b(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x604);
        instr.set_funct3(1);
        instr.0
    }

    pub fn sext_h(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::OpImm);
        instr.set_rd(rd);
        instr.set_rs(rs);
        instr.set_imm(0x605);
        instr.set_funct3(1);
        instr.0
    }

    pub fn zext_h(rd: XReg, rs: XReg) -> u32 {
        let mut instr = RvInstr32R(0);
        instr.set_opcode(RvInstr32Opcode::Op);
        instr.set_rd(rd);
        instr.set_rs1(rs);
        instr.set_rs2(XReg::X0);
        instr.set_funct3(4);
        instr.set_funct7(RvInstr32OpFunct7::Zext.into());
        instr.0
    }

    // load immediate (first instruction)
    pub fn li0(rd: XReg, imm: u32) -> u32 {
        let v = (imm >> 12) + if imm & 0x800 == 0x800 { 1 } else { 0 };
        lui(rd, v as i32)
    }

    // load immediate (second instruction)
    pub fn li1(rd: XReg, imm: u32) -> u32 {
        addi(rd, rd, (imm & 0xfff) as i32)
    }

    /// Encode Load Upper Immediate (`lui`) instruction
    pub fn lui(rd: XReg, imm: i32) -> u32 {
        let mut instr = RvInstr32U(0);
        instr.set_opcode(RvInstr32Opcode::Lui);
        instr.set_rd(rd);
        instr.set_imm(imm);
        instr.0
    }

    branch_instr!(beq, Beq);
    branch_instr!(bne, Bne);
    branch_instr!(blt, Blt);
    branch_instr!(bge, Bge);
    branch_instr!(bltu, Bltu);
    branch_instr!(bgeu, Bgeu);

    pub fn jalr(rd: XReg, rs1: XReg, imm: i32) -> u32 {
        let mut instr = RvInstr32I(0);
        instr.set_opcode(RvInstr32Opcode::Jalr);
        instr.set_rd(rd);
        instr.set_funct3(0);
        instr.set_rs(rs1);
        instr.set_imm(imm);
        instr.0
    }

    pub fn jal(rd: XReg, imm: u32) -> u32 {
        let mut instr = RvInstr32J(0);
        instr.set_opcode(RvInstr32Opcode::Jal);
        instr.set_rd(rd);
        instr.set_imm(imm);
        instr.0
    }

    op_system_instr!(ecall, Priv, Ecall);
    op_system_instr!(ebreak, Priv, Ebreak);
    op_system_instr!(csrrw, Csrrw);
    op_system_instr!(csrrs, Csrrs);
    op_system_instr!(csrrc, Csrrc);
    op_system_instr!(csrrwi, Csrrwi);
    op_system_instr!(csrrsi, Csrrsi);
    op_system_instr!(csrrci, Csrrci);

    #[test]
    fn test_sign_extend() {
        for i in 0..0x800 {
            assert_eq!(i, sign_extend(i));
        }
        for i in 0x800..0x1000 {
            assert_eq!(0xffff_f000 | i, sign_extend(i));
        }
    }
}
