/*++

Licensed under the Apache-2.0 license.

File Name:

    bit.rs

Abstract:

    File contains implementation of bit manipulation instructions (Zba, Zbb, Zbc, Zbs).

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32I, RvInstr32OpFunct7, RvInstr32OpImmFunct7, RvInstr32R};
use crate::xreg_file::XReg;
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvData;

/// Carry-less multiply, low part
fn clmul(a: u32, b: u32) -> u32 {
    let mut output = 0;
    for i in 0..32 {
        if (b >> i) & 1 == 1 {
            output ^= a << i;
        }
    }
    output
}

/// Carry-less multiply, high part
fn clmulh(a: u32, b: u32) -> u32 {
    let mut output = 0;
    for i in 1..32 {
        if (b >> i) & 1 == 1 {
            output ^= a >> (32 - i);
        }
    }
    output
}

/// Carry-less multiply, reversed
fn clmulr(a: u32, b: u32) -> u32 {
    let mut output = 0;
    for i in 0..32 {
        if (b >> i) & 1 == 1 {
            output ^= a >> (32 - i - 1);
        }
    }
    output
}

impl<TBus: Bus> Cpu<TBus> {
    /// If this matches a bit manipulation instruction, execute it and return Some(result).
    /// Otherwise, return None.
    pub(crate) fn exec_bit_instr_op(
        &mut self,
        instr: RvInstr32R,
        val1: u32,
        val2: u32,
    ) -> Option<RvData> {
        // Decode the instruction
        match (RvInstr32OpFunct7::from(instr.funct7()), instr.funct3()) {
            // Shift 1 and Add, sh1add
            (RvInstr32OpFunct7::Sh1add, 2) => Some(val1.wrapping_shl(1).wrapping_add(val2)),
            // Shift 2 and Add, sh2add
            (RvInstr32OpFunct7::Sh1add, 4) => Some(val1.wrapping_shl(2).wrapping_add(val2)),
            // Shift 3 and Add, sh3add
            (RvInstr32OpFunct7::Sh1add, 6) => Some(val1.wrapping_shl(3).wrapping_add(val2)),
            // Bit Set, bset
            (RvInstr32OpFunct7::Bset, 1) => Some(val1 | (1 << (val2 & 0x1f))),
            // Single-Bit Invert, binv
            (RvInstr32OpFunct7::Binv, 1) => Some(val1 ^ (1 << (val2 & 0x1f))),
            // Bit Clear, bclr
            (RvInstr32OpFunct7::Bclr, 1) => Some(val1 & !(1 << (val2 & 0x1f))),
            // Bit Extract, bext
            (RvInstr32OpFunct7::Bclr, 5) => Some((val1 >> (val2 & 0x1f)) & 1),
            // Carry-less multiply low part, clmul
            (RvInstr32OpFunct7::MinMaxClmul, 1) => Some(clmul(val1, val2)),
            // Carry-less multiply high part, clmulh
            (RvInstr32OpFunct7::MinMaxClmul, 3) => Some(clmulh(val1, val2)),
            // Carry-less multiply reversed, clmulr
            (RvInstr32OpFunct7::MinMaxClmul, 2) => Some(clmulr(val1, val2)),
            // Maximum, max
            (RvInstr32OpFunct7::MinMaxClmul, 6) => Some(i32::max(val1 as i32, val2 as i32) as u32),
            // Maximum unsigned, maxu
            (RvInstr32OpFunct7::MinMaxClmul, 7) => Some(u32::max(val1, val2)),
            // Minimum, min
            (RvInstr32OpFunct7::MinMaxClmul, 4) => Some(i32::min(val1 as i32, val2 as i32) as u32),
            // Minimum unsigned, min
            (RvInstr32OpFunct7::MinMaxClmul, 5) => Some(u32::min(val1, val2)),
            // And Invert, andn
            (RvInstr32OpFunct7::Andn, 7) => Some(val1 & !val2),
            // Or Invert, orn
            (RvInstr32OpFunct7::Orn, 6) => Some(val1 | !val2),
            // Exclusive Nor, xnor
            (RvInstr32OpFunct7::Xnor, 4) => Some(!(val1 ^ val2)),
            // Zero-extend halfword, zext.h
            (RvInstr32OpFunct7::Zext, 4) if instr.rs2() == XReg::X0 => Some(val1 & 0xffff),
            // Rotate left, rol
            (RvInstr32OpFunct7::Rotate, 1) => Some(val1.rotate_left(val2 & 0x1f)),
            // Rotate right, ror
            (RvInstr32OpFunct7::Rotate, 5) => Some(val1.rotate_right(val2 & 0x1f)),
            _ => None,
        }
    }
    pub(crate) fn exec_bit_instr_op_imm(&mut self, instr: RvInstr32I, reg: u32) -> Option<RvData> {
        // Decode the instruction
        let imm = instr.imm();
        match (RvInstr32OpImmFunct7::from(instr.funct7()), instr.funct3()) {
            // Bit Set Immediate, bseti
            (RvInstr32OpImmFunct7::Orc, 1) => Some(reg | (1 << (imm & 0x1f))),
            // Bitwise OR-Combine byte granule, orc.b
            (RvInstr32OpImmFunct7::Orc, 5) if instr.funct5() == 0b0_0111 => {
                let reg_bytes = reg.to_le_bytes();
                Some(u32::from_le_bytes(core::array::from_fn(|i| {
                    if reg_bytes[i] != 0 {
                        0xff
                    } else {
                        0x00
                    }
                })))
            }
            // Single-Bit Invert Immediate, bseti
            (RvInstr32OpImmFunct7::Rev8, 1) => Some(reg ^ (1 << (imm & 0x1f))),
            // Bit Clear Immediate, bclri
            (RvInstr32OpImmFunct7::Bclr, 1) => Some(reg & !(1 << (imm & 0x1f))),
            // Bit Extract Immediate, bexti
            (RvInstr32OpImmFunct7::Bclr, 5) => Some((reg >> (imm & 0x1f)) & 1),
            // Rotate Right Immediate, rori
            (RvInstr32OpImmFunct7::Bitmanip, 5) => Some(reg.rotate_right(instr.shamt())),
            // Count leading zeroes, clz
            (RvInstr32OpImmFunct7::Bitmanip, 1) if instr.funct5() == 0b0_0000 => {
                Some(reg.leading_zeros())
            }
            // Count trailing zeroes, ctz
            (RvInstr32OpImmFunct7::Bitmanip, 1) if instr.funct5() == 0b0_0001 => {
                Some(reg.trailing_zeros())
            }
            // Count set bits, cpop
            (RvInstr32OpImmFunct7::Bitmanip, 1) if instr.funct5() == 0b0_0010 => {
                Some(reg.count_ones())
            }
            // Sign-extend byte, sext.b
            (RvInstr32OpImmFunct7::Bitmanip, 1) if instr.funct5() == 0b0_0100 => {
                Some(reg as i8 as i32 as u32)
            }
            // Sign-extend halfword, sext.h
            (RvInstr32OpImmFunct7::Bitmanip, 1) if instr.funct5() == 0b0_0101 => {
                Some(reg as i16 as i32 as u32)
            }
            // Byte-reverse register
            (RvInstr32OpImmFunct7::Rev8, 5) if instr.funct5() == 0b1_1000 => Some(reg.swap_bytes()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::identity_op)]
#[rustfmt::skip]
mod tests {
    use crate::{
        test_imm_dest_bypass, test_imm_op, test_imm_src1_bypass, test_imm_src1_eq_dest, test_imm_zero_dest, test_imm_zero_src1, test_r_dest_bypass, test_r_op, test_r_src1_eq_dest, test_rr_dest_bypass, test_rr_op, test_rr_src12_bypass, test_rr_src12_eq_dest, test_rr_src1_eq_dest, test_rr_src21_bypass, test_rr_src2_eq_dest, test_rr_zerodest, test_rr_zerosrc1, test_rr_zerosrc12, test_rr_zerosrc2
    };

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift 1 Add (`sh1add`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzba/sh1add.S
    // ---------------------------------------------------------------------------------------------
    test_rr_op!(test_sh1add_2, sh1add, 0x0000_0000, 0x0000_0000, 0x0000_0000);
    test_rr_op!(test_sh1add_3, sh1add, 0x0000_0003, 0x0000_0001, 0x0000_0001);
    test_rr_op!(test_sh1add_4, sh1add, 0x0000_000d, 0x0000_0003, 0x0000_0007);
    test_rr_op!(test_sh1add_5, sh1add, 0xffff_8000, 0x0000_0000, 0xffff_8000);
    test_rr_op!(test_sh1add_6, sh1add, 0x0000_0000, 0x8000_0000, 0x0000_0000);
    test_rr_op!(test_sh1add_7, sh1add, 0xffff_8000, 0x8000_0000, 0xffff_8000);
    test_rr_op!(test_sh1add_8, sh1add, 0x0000_7fff, 0x0000_0000, 0x0000_7fff);
    test_rr_op!(test_sh1add_9, sh1add, 0xffff_fffe, 0x7fff_ffff, 0x0000_0000);
    test_rr_op!(test_sh1add_10, sh1add, 0x0000_7ffd, 0x7fff_ffff, 0x0000_7fff);
    test_rr_op!(test_sh1add_11, sh1add, 0x0000_7fff, 0x8000_0000, 0x0000_7fff);
    test_rr_op!(test_sh1add_12, sh1add, 0xffff_7ffe, 0x7fff_ffff, 0xffff_8000);
    test_rr_op!(test_sh1add_13, sh1add, 0xffff_ffff, 0x0000_0000, 0xffff_ffff);
    test_rr_op!(test_sh1add_14, sh1add, 0xffff_ffff, 0xffff_ffff, 0x0000_0001);
    test_rr_op!(test_sh1add_15, sh1add, 0xffff_fffd, 0xffff_ffff, 0xffff_ffff);
    test_rr_op!(test_sh1add_16, sh1add, 0x8000_0001, 0x0000_0001, 0x7fff_ffff);

    test_rr_src1_eq_dest!(test_sh1add_17, sh1add, 37, 13, 11);
    test_rr_src2_eq_dest!(test_sh1add_18, sh1add, 39, 14, 11);
    test_rr_src12_eq_dest!(test_sh1add_19, sh1add, 39, 13);

    test_rr_dest_bypass!(test_sh1add_20, 0 , sh1add, 37, 13, 11);
    test_rr_dest_bypass!(test_sh1add_21, 1 , sh1add, 39, 14, 11);
    test_rr_dest_bypass!(test_sh1add_22, 2 , sh1add, 41, 15, 11);

    test_rr_src12_bypass!(test_sha1add_23, 0, 0, sh1add, 37, 13, 11);
    test_rr_src12_bypass!(test_sha1add_24, 0, 1, sh1add, 39, 14, 11);
    test_rr_src12_bypass!(test_sha1add_25, 0, 2, sh1add, 41, 15, 11);
    test_rr_src12_bypass!(test_sha1add_26, 1, 0, sh1add, 37, 13, 11);
    test_rr_src12_bypass!(test_sha1add_27, 1, 1, sh1add, 39, 14, 11);
    test_rr_src12_bypass!(test_sha1add_28, 2, 0, sh1add, 41, 15, 11);

    test_rr_src21_bypass!(test_sha1add_29, 0, 0, sh1add, 37, 13, 11);
    test_rr_src21_bypass!(test_sha1add_30, 0, 1, sh1add, 39, 14, 11);
    test_rr_src21_bypass!(test_sha1add_31, 0, 2, sh1add, 41, 15, 11);
    test_rr_src21_bypass!(test_sha1add_32, 1, 0, sh1add, 37, 13, 11);
    test_rr_src21_bypass!(test_sha1add_33, 1, 1, sh1add, 39, 14, 11);
    test_rr_src21_bypass!(test_sha1add_34, 2, 0, sh1add, 41, 15, 11);

    test_rr_zerosrc1!(test_sh1add_35, sh1add, 15, 15);
    test_rr_zerosrc2!(test_sh1add_36, sh1add, 64, 32);
    test_rr_zerosrc12!(test_sh1add_37, sh1add, 0);
    test_rr_zerodest!(test_sh1add_38, sh1add, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift 2 Add (`sh2add`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzba/sh2add.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_sh2add_2,  sh2add, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_sh2add_3,  sh2add, 0x00000005, 0x00000001, 0x00000001);
    test_rr_op!(test_sh2add_4,  sh2add, 0x00000013, 0x00000003, 0x00000007);

    test_rr_op!(test_sh2add_5,  sh2add, 0xffff8000, 0x00000000, 0xffff8000);
    test_rr_op!(test_sh2add_6,  sh2add, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_sh2add_7,  sh2add, 0xffff8000, 0x80000000, 0xffff8000);

    test_rr_op!(test_sh2add_8,  sh2add, 0x00007fff, 0x00000000, 0x00007fff);
    test_rr_op!(test_sh2add_9,  sh2add, 0xfffffffc, 0x7fffffff, 0x00000000);
    test_rr_op!(test_sh2add_10, sh2add, 0x00007ffb, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_sh2add_11, sh2add, 0x00007fff, 0x80000000, 0x00007fff);
    test_rr_op!(test_sh2add_12, sh2add, 0xffff7ffc, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_sh2add_13, sh2add, 0xffffffff, 0x00000000, 0xffffffff);
    test_rr_op!(test_sh2add_14, sh2add, 0xfffffffd, 0xffffffff, 0x00000001);
    test_rr_op!(test_sh2add_15, sh2add, 0xfffffffb, 0xffffffff, 0xffffffff);

    test_rr_op!(test_sh2add_16, sh2add, 0x80000003, 0x00000001, 0x7fffffff);

    test_rr_src1_eq_dest!(test_sh2add_17, sh2add, 63, 13, 11);
    test_rr_src2_eq_dest!(test_sh2add_18, sh2add, 67, 14, 11);
    test_rr_src12_eq_dest!(test_sh2add_19, sh2add, 65, 13);

    test_rr_dest_bypass!(test_sh2add_20, 0, sh2add, 63, 13, 11);
    test_rr_dest_bypass!(test_sh2add_21, 1, sh2add, 67, 14, 11);
    test_rr_dest_bypass!(test_sh2add_22, 2, sh2add, 71, 15, 11);

    test_rr_src12_bypass!(test_sh2add_23, 0, 0, sh2add, 63, 13, 11);
    test_rr_src12_bypass!(test_sh2add_24, 0, 1, sh2add, 67, 14, 11);
    test_rr_src12_bypass!(test_sh2add_25, 0, 2, sh2add, 71, 15, 11);
    test_rr_src12_bypass!(test_sh2add_26, 1, 0, sh2add, 63, 13, 11);
    test_rr_src12_bypass!(test_sh2add_27, 1, 1, sh2add, 67, 14, 11);
    test_rr_src12_bypass!(test_sh2add_28, 2, 0, sh2add, 71, 15, 11);

    test_rr_src21_bypass!(test_sh2add_29, 0, 0, sh2add, 63, 13, 11);
    test_rr_src21_bypass!(test_sh2add_30, 0, 1, sh2add, 67, 14, 11);
    test_rr_src21_bypass!(test_sh2add_31, 0, 2, sh2add, 71, 15, 11);
    test_rr_src21_bypass!(test_sh2add_32, 1, 0, sh2add, 63, 13, 11);
    test_rr_src21_bypass!(test_sh2add_33, 1, 1, sh2add, 67, 14, 11);
    test_rr_src21_bypass!(test_sh2add_34, 2, 0, sh2add, 71, 15, 11);

    test_rr_zerosrc1!(test_sh2add_35, sh2add, 15, 15);
    test_rr_zerosrc2!(test_sh2add_36, sh2add, 128, 32);
    test_rr_zerosrc12!(test_sh2add_37, sh2add, 0);
    test_rr_zerodest!(test_sh2add_38, sh2add, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Shift 3 Add (`sh3add`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzba/sh3add.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_sh3add_2,  sh3add, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_sh3add_3,  sh3add, 0x00000009, 0x00000001, 0x00000001);
    test_rr_op!(test_sh3add_4,  sh3add, 0x0000001f, 0x00000003, 0x00000007);

    test_rr_op!(test_sh3add_5,  sh3add, 0xffff8000, 0x00000000, 0xffff8000);
    test_rr_op!(test_sh3add_6,  sh3add, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_sh3add_7,  sh3add, 0xffff8000, 0x80000000, 0xffff8000);

    test_rr_op!(test_sh3add_8,  sh3add, 0x00007fff, 0x00000000, 0x00007fff);
    test_rr_op!(test_sh3add_9,  sh3add, 0xfffffff8, 0x7fffffff, 0x00000000);
    test_rr_op!(test_sh3add_10, sh3add, 0x00007ff7, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_sh3add_11, sh3add, 0x00007fff, 0x80000000, 0x00007fff);
    test_rr_op!(test_sh3add_12, sh3add, 0xffff7ff8, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_sh3add_13, sh3add, 0xffffffff, 0x00000000, 0xffffffff);
    test_rr_op!(test_sh3add_14, sh3add, 0xfffffff9, 0xffffffff, 0x00000001);
    test_rr_op!(test_sh3add_15, sh3add, 0xfffffff7, 0xffffffff, 0xffffffff);

    test_rr_op!(test_sh3add_16, sh3add, 0x80000007, 0x00000001, 0x7fffffff);

    test_rr_src1_eq_dest!(test_sh3add_17, sh3add, 115, 13, 11);
    test_rr_src2_eq_dest!(test_sh3add_18, sh3add, 123, 14, 11);
    test_rr_src12_eq_dest!(test_sh3add_19, sh3add, 117, 13);

    test_rr_dest_bypass!(test_sh3add_20, 0, sh3add, 115, 13, 11);
    test_rr_dest_bypass!(test_sh3add_21, 1, sh3add, 123, 14, 11);
    test_rr_dest_bypass!(test_sh3add_22, 2, sh3add, 131, 15, 11);

    test_rr_src12_bypass!(test_sh3add_23, 0, 0, sh3add, 115, 13, 11);
    test_rr_src12_bypass!(test_sh3add_24, 0, 1, sh3add, 123, 14, 11);
    test_rr_src12_bypass!(test_sh3add_25, 0, 2, sh3add, 131, 15, 11);
    test_rr_src12_bypass!(test_sh3add_26, 1, 0, sh3add, 115, 13, 11);
    test_rr_src12_bypass!(test_sh3add_27, 1, 1, sh3add, 123, 14, 11);
    test_rr_src12_bypass!(test_sh3add_28, 2, 0, sh3add, 131, 15, 11);

    test_rr_src21_bypass!(test_sh3add_29, 0, 0, sh3add, 115, 13, 11);
    test_rr_src21_bypass!(test_sh3add_30, 0, 1, sh3add, 123, 14, 11);
    test_rr_src21_bypass!(test_sh3add_31, 0, 2, sh3add, 131, 15, 11);
    test_rr_src21_bypass!(test_sh3add_32, 1, 0, sh3add, 115, 13, 11);
    test_rr_src21_bypass!(test_sh3add_33, 1, 1, sh3add, 123, 14, 11);
    test_rr_src21_bypass!(test_sh3add_34, 2, 0, sh3add, 131, 15, 11);

    test_rr_zerosrc1!(test_sh3add_35, sh3add, 15, 15);
    test_rr_zerosrc2!(test_sh3add_36, sh3add, 256, 32);
    test_rr_zerosrc12!(test_sh3add_37, sh3add, 0);
    test_rr_zerodest!(test_sh3add_38, sh3add, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Set (`bset`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bset.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_bset_2,  bset, 0xff00ff01, 0xff00ff00, 0);
    test_rr_op!(test_bset_3,  bset, 0x00ff00ff, 0x00ff00ff, 1);
    test_rr_op!(test_bset_4,  bset, 0xff00ff00, 0xff00ff00, 8);
    test_rr_op!(test_bset_5,  bset, 0x0ff04ff0, 0x0ff00ff0, 14);
    test_rr_op!(test_bset_6,  bset, 0x0ff00ff0, 0x0ff00ff0, 27);

    test_rr_op!(test_bset_7,  bset, 0x00000001, 0x00000001, 0);
    test_rr_op!(test_bset_8,  bset, 0x00000003, 0x00000001, 1);
    test_rr_op!(test_bset_9,  bset, 0x00000081, 0x00000001, 7);
    test_rr_op!(test_bset_10,  bset, 0x00004001, 0x00000001, 14);
    test_rr_op!(test_bset_11,  bset, 0x80000001, 0x00000001, 31);

    test_rr_op!(test_bset_12, bset, 0x21212121, 0x21212121, 0);
    test_rr_op!(test_bset_13, bset, 0x21212123, 0x21212121, 1);
    test_rr_op!(test_bset_14, bset, 0x212121a1, 0x21212121, 7);
    test_rr_op!(test_bset_15, bset, 0x21212121, 0x21212121, 13);
    test_rr_op!(test_bset_16, bset, 0x84848484, 0x84848484, 31);

    test_rr_op!(test_bset_17, bset, 0x21212121, 0x21212121, 0xffffffc0);
    test_rr_op!(test_bset_18, bset, 0x21212123, 0x21212121, 0xffffffc1);
    test_rr_op!(test_bset_19, bset, 0x212121a1, 0x21212121, 0xffffffc7);
    test_rr_op!(test_bset_20, bset, 0x8484c484, 0x84848484, 0xffffffce);

    test_rr_src1_eq_dest!(test_bset_22, bset, 0x00000081, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_bset_23, bset, 0x00005551, 0x00005551, 14);
    test_rr_src12_eq_dest!(test_bset_24, bset, 11, 3);

    test_rr_dest_bypass!(test_bset_25, 0, bset, 0xff00ff01, 0xff00ff00, 0);
    test_rr_dest_bypass!(test_bset_26, 1, bset, 0x00ff00ff, 0x00ff00ff, 1);
    test_rr_dest_bypass!(test_bset_27, 2, bset, 0xff00ff00, 0xff00ff00, 8);

    test_rr_src12_bypass!(test_bset_28, 0, 0, bset, 0xff00ff01, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bset_29, 0, 1, bset, 0x00ff00ff, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bset_30, 0, 2, bset, 0xff00ff00, 0xff00ff00, 8);
    test_rr_src12_bypass!(test_bset_31, 1, 0, bset, 0xff00ff01, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bset_32, 1, 1, bset, 0x00ff00ff, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bset_33, 2, 0, bset, 0xff00ff00, 0xff00ff00, 8);

    test_rr_src21_bypass!(test_bset_34, 0, 0, bset, 0xff00ff00, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bset_35, 0, 1, bset, 0x0ff04ff0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bset_36, 0, 2, bset, 0x0ff00ff0, 0x0ff00ff0, 27);
    test_rr_src21_bypass!(test_bset_37, 1, 0, bset, 0xff00ff00, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bset_38, 1, 1, bset, 0x0ff04ff0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bset_39, 2, 0, bset, 0x0ff00ff0, 0x0ff00ff0, 27);

    test_rr_zerosrc1!(test_bset_40, bset, 0x00008000, 15);
    test_rr_zerosrc2!(test_bset_41, bset, 33, 32);
    test_rr_zerosrc12!(test_bset_42, bset, 1);
    test_rr_zerodest!(test_bset_43, bset, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Clear (`bclr`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bclr.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_bclr_2,  bclr, 0xff00ff00, 0xff00ff00, 0);
    test_rr_op!(test_bclr_3,  bclr, 0x00ff00fd, 0x00ff00ff, 1);
    test_rr_op!(test_bclr_4,  bclr, 0xff00fe00, 0xff00ff00, 8);
    test_rr_op!(test_bclr_5,  bclr, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_rr_op!(test_bclr_6,  bclr, 0x07f00ff0, 0x0ff00ff0, 27);

    test_rr_op!(test_bclr_7,  bclr, 0xfffffffe, 0xffffffff, 0);
    test_rr_op!(test_bclr_8,  bclr, 0xfffffffd, 0xffffffff, 1);
    test_rr_op!(test_bclr_9,  bclr, 0xffffff7f, 0xffffffff, 7);
    test_rr_op!(test_bclr_10, bclr, 0xffffbfff, 0xffffffff, 14);
    test_rr_op!(test_bclr_11, bclr, 0xf7ffffff, 0xffffffff, 27);

    test_rr_op!(test_bclr_12, bclr, 0x21212120, 0x21212121, 0);
    test_rr_op!(test_bclr_13, bclr, 0x21212121, 0x21212121, 1);
    test_rr_op!(test_bclr_14, bclr, 0x21212121, 0x21212121, 7);
    test_rr_op!(test_bclr_15, bclr, 0x21210121, 0x21212121, 13);
    test_rr_op!(test_bclr_16, bclr, 0x04848484, 0x84848484, 31);

    // Verify that shifts only use bottom five (rv32) bits

    test_rr_op!(test_bclr_17, bclr, 0x21212120, 0x21212121, 0xffffffc0);
    test_rr_op!(test_bclr_18, bclr, 0x21212121, 0x21212121, 0xffffffc1);
    test_rr_op!(test_bclr_19, bclr, 0x21212121, 0x21212121, 0xffffffc7);
    test_rr_op!(test_bclr_20, bclr, 0x84848484, 0x84848484, 0xffffffce);

    test_rr_src1_eq_dest!(test_bclr_22, bclr, 0x00000001, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_bclr_23, bclr, 0x00001551, 0x00005551, 14);
    test_rr_src12_eq_dest!(test_bclr_24, bclr, 3, 3);

    test_rr_dest_bypass!(test_bclr_25, 0, bclr, 0xff00ff00, 0xff00ff00, 0);
    test_rr_dest_bypass!(test_bclr_26, 1, bclr, 0x00ff00fd, 0x00ff00ff, 1);
    test_rr_dest_bypass!(test_bclr_27, 2, bclr, 0xff00fe00, 0xff00ff00, 8);

    test_rr_src12_bypass!(test_bclr_28, 0, 0, bclr, 0xff00ff00, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bclr_29, 0, 1, bclr, 0x00ff00fd, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bclr_30, 0, 2, bclr, 0xff00fe00, 0xff00ff00, 8);
    test_rr_src12_bypass!(test_bclr_31, 1, 0, bclr, 0xff00ff00, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bclr_32, 1, 1, bclr, 0x00ff00fd, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bclr_33, 2, 0, bclr, 0xff00fe00, 0xff00ff00, 8);

    test_rr_src21_bypass!(test_bclr_34, 0, 0, bclr, 0xff00fe00, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bclr_35, 0, 1, bclr, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bclr_36, 0, 2, bclr, 0x07f00ff0, 0x0ff00ff0, 27);
    test_rr_src21_bypass!(test_bclr_37, 1, 0, bclr, 0xff00fe00, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bclr_38, 1, 1, bclr, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bclr_39, 2, 0, bclr, 0x07f00ff0, 0x0ff00ff0, 27);

    test_rr_zerosrc1!(test_bclr_40, bclr, 0, 15);
    test_rr_zerosrc2!(test_bclr_41, bclr, 32, 32);
    test_rr_zerosrc12!(test_bclr_42, bclr, 0);
    test_rr_zerodest!(test_bclr_43, bclr, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Extract (`bext`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bext.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_bext_2,  bext, 0, 0xff00ff00, 0);
    test_rr_op!(test_bext_3,  bext, 1, 0x00ff00ff, 1);
    test_rr_op!(test_bext_4,  bext, 1, 0xff00ff00, 8);
    test_rr_op!(test_bext_5,  bext, 0, 0x0ff00ff0, 14);
    test_rr_op!(test_bext_6,  bext, 1, 0x0ff00ff0, 27);

    test_rr_op!(test_bext_7,  bext, 1, 0xffffffff, 0);
    test_rr_op!(test_bext_8,  bext, 1, 0xffffffff, 1);
    test_rr_op!(test_bext_9,  bext, 1, 0xffffffff, 7);
    test_rr_op!(test_bext_10, bext, 1, 0xffffffff, 14);
    test_rr_op!(test_bext_11, bext, 1, 0xffffffff, 27);

    test_rr_op!(test_bext_12, bext, 1, 0x21212121, 0);
    test_rr_op!(test_bext_13, bext, 0, 0x21212121, 1);
    test_rr_op!(test_bext_14, bext, 0, 0x21212121, 7);
    test_rr_op!(test_bext_15, bext, 1, 0x21212121, 13);
    test_rr_op!(test_bext_16, bext, 1, 0x84848484, 31);

    // Verify that shifts only use bottom five bits

    test_rr_op!(test_bext_17, bext, 1, 0x21212121, 0xffffffc0);
    test_rr_op!(test_bext_18, bext, 0, 0x21212121, 0xffffffc1);
    test_rr_op!(test_bext_19, bext, 0, 0x21212121, 0xffffffc7);
    test_rr_op!(test_bext_20, bext, 0, 0x84848484, 0xffffffce);

    test_rr_src1_eq_dest!(test_bext_22, bext, 0, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_bext_23, bext, 1, 0x00005551, 14);
    test_rr_src12_eq_dest!(test_bext_24, bext, 0, 3);

    test_rr_dest_bypass!(test_bext_25, 0, bext, 0, 0xff00ff00, 0);
    test_rr_dest_bypass!(test_bext_26, 1, bext, 1, 0x00ff00ff, 1);
    test_rr_dest_bypass!(test_bext_27, 2, bext, 1, 0xff00ff00, 8);

    test_rr_src12_bypass!(test_bext_28, 0, 0, bext, 0, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bext_29, 0, 1, bext, 1, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bext_30, 0, 2, bext, 1, 0xff00ff00, 8);
    test_rr_src12_bypass!(test_bext_31, 1, 0, bext, 0, 0xff00ff00, 0);
    test_rr_src12_bypass!(test_bext_32, 1, 1, bext, 1, 0x00ff00ff, 1);
    test_rr_src12_bypass!(test_bext_33, 2, 0, bext, 1, 0xff00ff00, 8);

    test_rr_src21_bypass!(test_bext_34, 0, 0, bext, 1, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bext_35, 0, 1, bext, 0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bext_36, 0, 2, bext, 1, 0x0ff00ff0, 27);
    test_rr_src21_bypass!(test_bext_37, 1, 0, bext, 1, 0xff00ff00, 8);
    test_rr_src21_bypass!(test_bext_38, 1, 1, bext, 0, 0x0ff00ff0, 14);
    test_rr_src21_bypass!(test_bext_39, 2, 0, bext, 1, 0x0ff00ff0, 27);

    test_rr_zerosrc1!(test_bext_40, bext, 0, 15);
    test_rr_zerosrc2!(test_bext_41, bext, 0, 32);
    test_rr_zerosrc12!(test_bext_42, bext, 0);
    test_rr_zerodest!(test_bext_43, bext, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Set Immediate (`bseti`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bseti.S
    // ---------------------------------------------------------------------------------------------

    test_imm_op!(test_bseti_2,  bseti, 0xff00ff01, 0xff00ff00, 0);
    test_imm_op!(test_bseti_3,  bseti, 0x00ff00ff, 0x00ff00ff, 1);
    test_imm_op!(test_bseti_4,  bseti, 0xff00ff00, 0xff00ff00, 8);
    test_imm_op!(test_bseti_5,  bseti, 0x0ff04ff0, 0x0ff00ff0, 14);
    test_imm_op!(test_bseti_6,  bseti, 0x0ff00ff0, 0x0ff00ff0, 27);

    test_imm_op!(test_bseti_7,  bseti, 0x00000001, 0x00000001, 0);
    test_imm_op!(test_bseti_8,  bseti, 0x00000003, 0x00000001, 1);
    test_imm_op!(test_bseti_9,  bseti, 0x00000081, 0x00000001, 7);
    test_imm_op!(test_bseti_10,  bseti, 0x00004001, 0x00000001, 14);
    test_imm_op!(test_bseti_11,  bseti, 0x80000001, 0x00000001, 31);

    test_imm_op!(test_bseti_12, bseti, 0x21212121, 0x21212121, 0);
    test_imm_op!(test_bseti_13, bseti, 0x21212123, 0x21212121, 1);
    test_imm_op!(test_bseti_14, bseti, 0x212121a1, 0x21212121, 7);
    test_imm_op!(test_bseti_15, bseti, 0x21212121, 0x21212121, 13);
    test_imm_op!(test_bseti_16, bseti, 0x84848484, 0x84848484, 31);

    test_imm_src1_eq_dest!(test_bseti_17, bseti, 0x00000081, 0x00000001, 7);

    test_imm_dest_bypass!(test_bseti_18, 0, bseti, 0xff00ff01, 0xff00ff00, 0);
    test_imm_dest_bypass!(test_bseti_19, 1, bseti, 0x00ff00ff, 0x00ff00ff, 1);
    test_imm_dest_bypass!(test_bseti_20, 2, bseti, 0xff00ff00, 0xff00ff00, 8);

    test_imm_src1_bypass!(test_bseti_21, 0, bseti, 0xff00ff00, 0xff00ff00, 8);
    test_imm_src1_bypass!(test_bseti_22, 1, bseti, 0x0ff04ff0, 0x0ff00ff0, 14);
    test_imm_src1_bypass!(test_bseti_23, 2, bseti, 0x0ff00ff0, 0x0ff00ff0, 27);

    test_imm_zero_src1!(test_bseti_24, bseti, 0x00008000, 15);
    test_imm_zero_dest!(test_bseti_25, bseti, 1024, 10);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Clear Immediate (`bclri`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bclri.S
    // ---------------------------------------------------------------------------------------------

    test_imm_op!(test_bclri_2,  bclri, 0xff00ff00, 0xff00ff00, 0);
    test_imm_op!(test_bclri_3,  bclri, 0x00ff00fd, 0x00ff00ff, 1);
    test_imm_op!(test_bclri_4,  bclri, 0xff00fe00, 0xff00ff00, 8);
    test_imm_op!(test_bclri_5,  bclri, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_imm_op!(test_bclri_6,  bclri, 0x07f00ff0, 0x0ff00ff0, 27);

    test_imm_op!(test_bclri_7,  bclri, 0xfffffffe, 0xffffffff, 0);
    test_imm_op!(test_bclri_8,  bclri, 0xfffffffd, 0xffffffff, 1);
    test_imm_op!(test_bclri_9,  bclri, 0xffffff7f, 0xffffffff, 7);
    test_imm_op!(test_bclri_10, bclri, 0xffffbfff, 0xffffffff, 14);
    test_imm_op!(test_bclri_11, bclri, 0xf7ffffff, 0xffffffff, 27);

    test_imm_op!(test_bclri_12, bclri, 0x21212120, 0x21212121, 0);
    test_imm_op!(test_bclri_13, bclri, 0x21212121, 0x21212121, 1);
    test_imm_op!(test_bclri_14, bclri, 0x21212121, 0x21212121, 7);
    test_imm_op!(test_bclri_15, bclri, 0x21210121, 0x21212121, 13);
    test_imm_op!(test_bclri_16, bclri, 0x04848484, 0x84848484, 31);

    test_imm_src1_eq_dest!(test_bclri_17, bclri, 0x00000001, 0x00000001, 7);

    test_imm_dest_bypass!(test_bclri_18, 0, bclri, 0xff00fe00, 0xff00ff00, 8);
    test_imm_dest_bypass!(test_bclri_19, 1, bclri, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_imm_dest_bypass!(test_bclri_20, 2, bclri, 0x07f00ff0, 0x0ff00ff0, 27);

    test_imm_src1_bypass!(test_bclri_21, 0, bclri, 0xff00fe00, 0xff00ff00, 8);
    test_imm_src1_bypass!(test_bclri_22, 1, bclri, 0x0ff00ff0, 0x0ff00ff0, 14);
    test_imm_src1_bypass!(test_bclri_23, 2, bclri, 0x07f00ff0, 0x0ff00ff0, 27);

    test_imm_zero_src1!(test_bclri_24, bclri, 0, 31);
    test_imm_zero_dest!(test_bclri_25, bclri, 33, 20);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bit Extract Immediate (`bexti`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/bexti.S
    // ---------------------------------------------------------------------------------------------

    test_imm_op!(test_bexti_2,  bexti, 0, 0xff00ff00, 0);
    test_imm_op!(test_bexti_3,  bexti, 1, 0x00ff00ff, 1);
    test_imm_op!(test_bexti_4,  bexti, 1, 0xff00ff00, 8);
    test_imm_op!(test_bexti_5,  bexti, 0, 0x0ff00ff0, 14);
    test_imm_op!(test_bexti_6,  bexti, 1, 0x0ff00ff0, 27);

    test_imm_op!(test_bexti_7,  bexti, 1, 0xffffffff, 0);
    test_imm_op!(test_bexti_8,  bexti, 1, 0xffffffff, 1);
    test_imm_op!(test_bexti_9,  bexti, 1, 0xffffffff, 7);
    test_imm_op!(test_bexti_10, bexti, 1, 0xffffffff, 14);
    test_imm_op!(test_bexti_11, bexti, 1, 0xffffffff, 27);

    test_imm_op!(test_bexti_12, bexti, 1, 0x21212121, 0);
    test_imm_op!(test_bexti_13, bexti, 0, 0x21212121, 1);
    test_imm_op!(test_bexti_14, bexti, 0, 0x21212121, 7);
    test_imm_op!(test_bexti_15, bexti, 1, 0x21212121, 13);
    test_imm_op!(test_bexti_16, bexti, 1, 0x84848484, 31);

    test_imm_src1_eq_dest!(test_bexti_17, bexti, 0, 0x00000001, 7);

    test_imm_dest_bypass!(test_bexti_18, 0, bexti, 1, 0xff00ff00, 8);
    test_imm_dest_bypass!(test_bexti_19, 1, bexti, 0, 0x0ff00ff0, 14);
    test_imm_dest_bypass!(test_bexti_20, 2, bexti, 1, 0x0ff00ff0, 27);

    test_imm_src1_bypass!(test_bexti_21, 0, bexti, 1, 0xff00ff00, 8);
    test_imm_src1_bypass!(test_bexti_22, 1, bexti, 0, 0x0ff00ff0, 14);
    test_imm_src1_bypass!(test_bexti_23, 2, bexti, 1, 0x0ff00ff0, 27);

    test_imm_zero_src1!(test_bexti_24, bexti, 0, 31);
    test_imm_zero_dest!(test_bexti_25, bexti, 33, 20);

    // ---------------------------------------------------------------------------------------------
    // Tests for And Invert (`andn`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/andn.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_andn_2, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_op!(test_andn_3, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_op!(test_andn_4, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_op!(test_andn_5, andn, 0x000f000f, 0xf00ff00f, 0xf0f0f0f0);

    test_rr_src1_eq_dest!(test_andn_6, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src2_eq_dest!(test_andn_7, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_eq_dest!(test_andn_8, andn, 0x00000000, 0xff00ff00);

    test_rr_dest_bypass!(test_andn_9,  0, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_dest_bypass!(test_andn_10, 1, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_dest_bypass!(test_andn_11, 2, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src12_bypass!(test_andn_12, 0, 0, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_andn_13, 0, 1, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_andn_14, 0, 2, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_andn_15, 1, 0, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_andn_16, 1, 1, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_andn_17, 2, 0, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src21_bypass!(test_andn_18, 0, 0, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_andn_19, 0, 1, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_andn_20, 0, 2, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_andn_21, 1, 0, andn, 0xf000f000, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_andn_22, 1, 1, andn, 0x0f000f00, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_andn_23, 2, 0, andn, 0x00f000f0, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_zerosrc1!(test_andn_24, andn, 0, 0xff00ff00);
    test_rr_zerosrc2!(test_andn_25, andn, 0x00ff00ff, 0x00ff00ff);
    test_rr_zerosrc12!(test_andn_26, andn, 0);
    test_rr_zerodest!(test_andn_27, andn, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests for Or Invert (`orn`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/orn.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_orn_2, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_op!(test_orn_3, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_op!(test_orn_4, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_op!(test_orn_5, orn, 0xff0fff0f, 0xf00ff00f, 0xf0f0f0f0);

    test_rr_src1_eq_dest!(test_orn_6, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src2_eq_dest!(test_orn_7, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_eq_dest!(test_orn_8, orn, 0xffffffff, 0xff00ff00);

    test_rr_dest_bypass!(test_orn_9,  0, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_dest_bypass!(test_orn_10, 1, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_dest_bypass!(test_orn_11, 2, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src12_bypass!(test_orn_12, 0, 0, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_orn_13, 0, 1, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_orn_14, 0, 2, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_orn_15, 1, 0, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_orn_16, 1, 1, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_orn_17, 2, 0, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src21_bypass!(test_orn_18, 0, 0, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_orn_19, 0, 1, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_orn_20, 0, 2, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_orn_21, 1, 0, orn, 0xfff0fff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_orn_22, 1, 1, orn, 0x0fff0fff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_orn_23, 2, 0, orn, 0xf0fff0ff, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_zerosrc1!(test_orn_24, orn, 0x00ff00ff, 0xff00ff00);
    test_rr_zerosrc2!(test_orn_25, orn, 0xffffffff, 0x00ff00ff);
    test_rr_zerosrc12!(test_orn_26, orn, 0xffffffff);
    test_rr_zerodest!(test_orn_27, orn, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests for Exclusive NOR (`xnor`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/xnor.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_xnor_2, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_op!(test_xnor_3, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_op!(test_xnor_4, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_op!(test_xnor_5, xnor, 0xff00ff00, 0xf00ff00f, 0xf0f0f0f0);

    test_rr_src1_eq_dest!(test_xnor_6, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src2_eq_dest!(test_xnor_7, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_eq_dest!(test_xnor_8, xnor, 0xffffffff, 0xff00ff00);

    test_rr_dest_bypass!(test_xnor_9,  0, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_dest_bypass!(test_xnor_10, 1, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_dest_bypass!(test_xnor_11, 2, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src12_bypass!(test_xnor_12, 0, 0, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_xnor_13, 0, 1, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_xnor_14, 0, 2, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_xnor_15, 1, 0, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src12_bypass!(test_xnor_16, 1, 1, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src12_bypass!(test_xnor_17, 2, 0, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_src21_bypass!(test_xnor_18, 0, 0, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_xnor_19, 0, 1, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_xnor_20, 0, 2, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_xnor_21, 1, 0, xnor, 0x0ff00ff0, 0xff00ff00, 0x0f0f0f0f);
    test_rr_src21_bypass!(test_xnor_22, 1, 1, xnor, 0x00ff00ff, 0x0ff00ff0, 0xf0f0f0f0);
    test_rr_src21_bypass!(test_xnor_23, 2, 0, xnor, 0xf00ff00f, 0x00ff00ff, 0x0f0f0f0f);

    test_rr_zerosrc1!(test_xnor_24, xnor, 0x00ff00ff, 0xff00ff00);
    test_rr_zerosrc2!(test_xnor_25, xnor, 0xff00ff00, 0x00ff00ff);
    test_rr_zerosrc12!(test_xnor_26, xnor, 0xffffffff);
    test_rr_zerodest!(test_xnor_27, xnor, 0x11111111, 0x22222222);

    // ---------------------------------------------------------------------------------------------
    // Tests for Maximum (`max`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/max.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_max_2,  max, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_max_3,  max, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_max_4,  max, 0x00000007, 0x00000003, 0x00000007);
    test_rr_op!(test_max_5,  max, 0x00000007, 0x00000007, 0x00000003);

    test_rr_op!(test_max_6,  max, 0x00000000, 0x00000000, 0xffff8000);
    test_rr_op!(test_max_7,  max, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_max_8,  max, 0xffff8000, 0x80000000, 0xffff8000);

    test_rr_op!(test_max_9,  max, 0x00007fff, 0x00000000, 0x00007fff);
    test_rr_op!(test_max_10, max, 0x7fffffff, 0x7fffffff, 0x00000000);
    test_rr_op!(test_max_11, max, 0x7fffffff, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_max_12, max, 0x00007fff, 0x80000000, 0x00007fff);
    test_rr_op!(test_max_13, max, 0x7fffffff, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_max_14, max, 0x00000000, 0x00000000, 0xffffffff);
    test_rr_op!(test_max_15, max, 0x00000001, 0xffffffff, 0x00000001);
    test_rr_op!(test_max_16, max, 0xffffffff, 0xffffffff, 0xffffffff);

    test_rr_src1_eq_dest!(test_max_17, max, 14, 14, 13);
    test_rr_src2_eq_dest!(test_max_18, max, 13, 11, 13);
    test_rr_src12_eq_dest!(test_max_19, max, 13, 13);

    test_rr_dest_bypass!(test_max_20, 0, max, 13, 11, 13);
    test_rr_dest_bypass!(test_max_21, 1, max, 14, 14, 13);
    test_rr_dest_bypass!(test_max_22, 2, max, 13, 12, 13);

    test_rr_src12_bypass!(test_max_23, 0, 0, max, 14, 14, 13);
    test_rr_src12_bypass!(test_max_24, 0, 1, max, 13, 11, 13);
    test_rr_src12_bypass!(test_max_25, 0, 2, max, 15, 15, 13);
    test_rr_src12_bypass!(test_max_26, 1, 0, max, 13, 10, 13);
    test_rr_src12_bypass!(test_max_27, 1, 1, max, 16, 16, 13);
    test_rr_src12_bypass!(test_max_28, 2, 0, max, 13,  9, 13);

    test_rr_src21_bypass!(test_max_29, 0, 0, max, 17, 17, 13);
    test_rr_src21_bypass!(test_max_30, 0, 1, max, 13,  8, 13);
    test_rr_src21_bypass!(test_max_31, 0, 2, max, 18, 18, 13);
    test_rr_src21_bypass!(test_max_32, 1, 0, max, 13,  7, 13);
    test_rr_src21_bypass!(test_max_33, 1, 1, max, 19, 19, 13);
    test_rr_src21_bypass!(test_max_34, 2, 0, max, 13,  6, 13);

    test_rr_zerosrc1!(test_max_35, max, 0, 0xffffffff);
    test_rr_zerosrc2!(test_max_36, max, 0, 0xffffffff);
    test_rr_zerosrc12!(test_max_37, max, 0);
    test_rr_zerodest!(test_max_38, max, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Maximum Unsigned (`maxu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/maxu.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_maxu_2,  maxu, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_maxu_3,  maxu, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_maxu_4,  maxu, 0x00000007, 0x00000003, 0x00000007);
    test_rr_op!(test_maxu_5,  maxu, 0x00000007, 0x00000007, 0x00000003);

    test_rr_op!(test_maxu_6,  maxu, 0xffff8000, 0x00000000, 0xffff8000);
    test_rr_op!(test_maxu_7,  maxu, 0x80000000, 0x80000000, 0x00000000);
    test_rr_op!(test_maxu_8,  maxu, 0xffff8000, 0x80000000, 0xffff8000);

    test_rr_op!(test_maxu_9,  maxu, 0x00007fff, 0x00000000, 0x00007fff);
    test_rr_op!(test_maxu_10, maxu, 0x7fffffff, 0x7fffffff, 0x00000000);
    test_rr_op!(test_maxu_11, maxu, 0x7fffffff, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_maxu_12, maxu, 0x80000000, 0x80000000, 0x00007fff);
    test_rr_op!(test_maxu_13, maxu, 0xffff8000, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_maxu_14, maxu, 0xffffffff, 0x00000000, 0xffffffff);
    test_rr_op!(test_maxu_15, maxu, 0xffffffff, 0xffffffff, 0x00000001);
    test_rr_op!(test_maxu_16, maxu, 0xffffffff, 0xffffffff, 0xffffffff);

    test_rr_src1_eq_dest!(test_maxu_17, maxu, 14, 14, 13);
    test_rr_src2_eq_dest!(test_maxu_18, maxu, 13, 11, 13);
    test_rr_src12_eq_dest!(test_maxu_19, maxu, 13, 13);

    test_rr_dest_bypass!(test_maxu_20, 0, maxu, 13, 11, 13);
    test_rr_dest_bypass!(test_maxu_21, 1, maxu, 14, 14, 13);
    test_rr_dest_bypass!(test_maxu_22, 2, maxu, 13, 12, 13);

    test_rr_src12_bypass!(test_maxu_23, 0, 0, maxu, 14, 14, 13);
    test_rr_src12_bypass!(test_maxu_24, 0, 1, maxu, 13, 11, 13);
    test_rr_src12_bypass!(test_maxu_25, 0, 2, maxu, 15, 15, 13);
    test_rr_src12_bypass!(test_maxu_26, 1, 0, maxu, 13, 10, 13);
    test_rr_src12_bypass!(test_maxu_27, 1, 1, maxu, 16, 16, 13);
    test_rr_src12_bypass!(test_maxu_28, 2, 0, maxu, 13,  9, 13);

    test_rr_src21_bypass!(test_maxu_29, 0, 0, maxu, 17, 17, 13);
    test_rr_src21_bypass!(test_maxu_30, 0, 1, maxu, 13,  8, 13);
    test_rr_src21_bypass!(test_maxu_31, 0, 2, maxu, 18, 18, 13);
    test_rr_src21_bypass!(test_maxu_32, 1, 0, maxu, 13,  7, 13);
    test_rr_src21_bypass!(test_maxu_33, 1, 1, maxu, 19, 19, 13);
    test_rr_src21_bypass!(test_maxu_34, 2, 0, maxu, 13,  6, 13);

    test_rr_zerosrc1!(test_maxu_35, maxu, 0xffffffff, 0xffffffff);
    test_rr_zerosrc2!(test_maxu_36, maxu, 0xffffffff, 0xffffffff);
    test_rr_zerosrc12!(test_maxu_37, maxu, 0);
    test_rr_zerodest!(test_maxu_38, maxu, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Maximum (`min`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/min.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_min_2,  min, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_min_3,  min, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_min_4,  min, 0x00000003, 0x00000003, 0x00000007);
    test_rr_op!(test_min_5,  min, 0x00000003, 0x00000007, 0x00000003);

    test_rr_op!(test_min_6,  min, 0xffff8000, 0x00000000, 0xffff8000);
    test_rr_op!(test_min_7,  min, 0x80000000, 0x80000000, 0x00000000);
    test_rr_op!(test_min_8,  min, 0x80000000, 0x80000000, 0xffff8000);

    test_rr_op!(test_min_9,  min, 0x00000000, 0x00000000, 0x00007fff);
    test_rr_op!(test_min_10, min, 0x00000000, 0x7fffffff, 0x00000000);
    test_rr_op!(test_min_11, min, 0x00007fff, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_min_12, min, 0x80000000, 0x80000000, 0x00007fff);
    test_rr_op!(test_min_13, min, 0xffff8000, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_min_14, min, 0xffffffff, 0x00000000, 0xffffffff);
    test_rr_op!(test_min_15, min, 0xffffffff, 0xffffffff, 0x00000001);
    test_rr_op!(test_min_16, min, 0xffffffff, 0xffffffff, 0xffffffff);

    test_rr_src1_eq_dest!(test_min_17, min, 13, 14, 13);
    test_rr_src2_eq_dest!(test_min_18, min, 11, 11, 13);
    test_rr_src12_eq_dest!(test_min_19, min, 13, 13);

    test_rr_dest_bypass!(test_min_20, 0, min, 11, 11, 13);
    test_rr_dest_bypass!(test_min_21, 1, min, 13, 14, 13);
    test_rr_dest_bypass!(test_min_22, 2, min, 12, 12, 13);

    test_rr_src12_bypass!(test_min_23, 0, 0, min, 13, 14, 13);
    test_rr_src12_bypass!(test_min_24, 0, 1, min, 11, 11, 13);
    test_rr_src12_bypass!(test_min_25, 0, 2, min, 13, 15, 13);
    test_rr_src12_bypass!(test_min_26, 1, 0, min, 10, 10, 13);
    test_rr_src12_bypass!(test_min_27, 1, 1, min, 13, 16, 13);
    test_rr_src12_bypass!(test_min_28, 2, 0, min, 9,  9, 13);

    test_rr_src21_bypass!(test_min_29, 0, 0, min, 13, 17, 13);
    test_rr_src21_bypass!(test_min_30, 0, 1, min, 8,  8, 13);
    test_rr_src21_bypass!(test_min_31, 0, 2, min, 13, 18, 13);
    test_rr_src21_bypass!(test_min_32, 1, 0, min, 7,  7, 13);
    test_rr_src21_bypass!(test_min_33, 1, 1, min, 13, 19, 13);
    test_rr_src21_bypass!(test_min_34, 2, 0, min, 6,  6, 13);

    test_rr_zerosrc1!(test_min_35, min, 0xffffffff, 0xffffffff);
    test_rr_zerosrc2!(test_min_36, min, 0xffffffff, 0xffffffff);
    test_rr_zerosrc12!(test_min_37, min, 0);
    test_rr_zerodest!(test_min_38, min, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Minimum Unsigned (`minu`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/minu.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_minu_2,  minu, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_minu_3,  minu, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_minu_4,  minu, 0x00000003, 0x00000003, 0x00000007);
    test_rr_op!(test_minu_5,  minu, 0x00000003, 0x00000007, 0x00000003);

    test_rr_op!(test_minu_6,  minu, 0x00000000, 0x00000000, 0xffff8000);
    test_rr_op!(test_minu_7,  minu, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_minu_8,  minu, 0x80000000, 0x80000000, 0xffff8000);

    test_rr_op!(test_minu_9,  minu, 0x00000000, 0x00000000, 0x00007fff);
    test_rr_op!(test_minu_10, minu, 0x00000000, 0x7fffffff, 0x00000000);
    test_rr_op!(test_minu_11, minu, 0x00007fff, 0x7fffffff, 0x00007fff);

    test_rr_op!(test_minu_12, minu, 0x00007fff, 0x80000000, 0x00007fff);
    test_rr_op!(test_minu_13, minu, 0x7fffffff, 0x7fffffff, 0xffff8000);

    test_rr_op!(test_minu_14, minu, 0x00000000, 0x00000000, 0xffffffff);
    test_rr_op!(test_minu_15, minu, 0x00000001, 0xffffffff, 0x00000001);
    test_rr_op!(test_minu_16, minu, 0xffffffff, 0xffffffff, 0xffffffff);

    test_rr_src1_eq_dest!(test_minu_17, minu, 13, 14, 13);
    test_rr_src2_eq_dest!(test_minu_18, minu, 11, 11, 13);
    test_rr_src12_eq_dest!(test_minu_19, minu, 13, 13);

    test_rr_dest_bypass!(test_minu_20, 0, minu, 11, 11, 13);
    test_rr_dest_bypass!(test_minu_21, 1, minu, 13, 14, 13);
    test_rr_dest_bypass!(test_minu_22, 2, minu, 12, 12, 13);

    test_rr_src12_bypass!(test_minu_23, 0, 0, minu, 13, 14, 13);
    test_rr_src12_bypass!(test_minu_24, 0, 1, minu, 11, 11, 13);
    test_rr_src12_bypass!(test_minu_25, 0, 2, minu, 13, 15, 13);
    test_rr_src12_bypass!(test_minu_26, 1, 0, minu, 10, 10, 13);
    test_rr_src12_bypass!(test_minu_27, 1, 1, minu, 13, 16, 13);
    test_rr_src12_bypass!(test_minu_28, 2, 0, minu, 9,  9, 13);

    test_rr_src21_bypass!(test_minu_29, 0, 0, minu, 13, 17, 13);
    test_rr_src21_bypass!(test_minu_30, 0, 1, minu, 8,  8, 13);
    test_rr_src21_bypass!(test_minu_31, 0, 2, minu, 13, 18, 13);
    test_rr_src21_bypass!(test_minu_32, 1, 0, minu, 7,  7, 13);
    test_rr_src21_bypass!(test_minu_33, 1, 1, minu, 13, 19, 13);
    test_rr_src21_bypass!(test_minu_34, 2, 0, minu, 6,  6, 13);

    test_rr_zerosrc1!(test_minu_35, minu, 0, 0xffffffff);
    test_rr_zerosrc2!(test_minu_36, minu, 0, 0xffffffff);
    test_rr_zerosrc12!(test_minu_37, minu, 0);
    test_rr_zerodest!(test_minu_38, minu, 16, 30);

    // ---------------------------------------------------------------------------------------------
    // Tests for Zero Extend Halfword (`zext.h`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/zext_h.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_zexth_2,  zext_h, 0x00000000, 0x00000000);
    test_r_op!(test_zexth_3,  zext_h, 0x00000001, 0x00000001);
    test_r_op!(test_zexth_4,  zext_h, 0x00000003, 0x00000003);

    test_r_op!(test_zexth_5,  zext_h, 0x00008000, 0xffff8000);
    test_r_op!(test_zexth_6,  zext_h, 0x00000000, 0x00800000);
    test_r_op!(test_zexth_7,  zext_h, 0x00008000, 0xffff8000);

    test_r_op!(test_zexth_8,  zext_h, 0x00007fff, 0x00007fff);
    test_r_op!(test_zexth_9,  zext_h, 0x0000ffff, 0x7fffffff);
    test_r_op!(test_zexth_10, zext_h, 0x0000ffff, 0x0007ffff);

    test_r_op!(test_zexth_11, zext_h, 0x00000000, 0x80000000);
    test_r_op!(test_zexth_12, zext_h, 0x00005000, 0x121f5000);

    test_r_op!(test_zexth_13, zext_h, 0x00000000, 0x00000000);
    test_r_op!(test_zexth_14, zext_h, 0x0000000e, 0x0000000e);
    test_r_op!(test_zexth_15, zext_h, 0x00001341, 0x20401341);

    test_r_src1_eq_dest!(test_zexth_16, zext_h, 0x0000000d, 13);
    test_r_src1_eq_dest!(test_zexth_17, zext_h, 0x0000000b, 11);

    test_r_dest_bypass!(test_zexth_18, 0, zext_h, 0x0000000d, 13);
    test_r_dest_bypass!(test_zexth_29, 1, zext_h, 0x00000013, 19);
    test_r_dest_bypass!(test_zexth_20, 2, zext_h, 0x00000022, 34);

    test_r_op!(test_zexth_21,  zext_h, 0x00008000, 0x007f8000);
    test_r_op!(test_zexth_22,  zext_h, 0x00008000, 0x00808000);
    test_r_op!(test_zexth_23,  zext_h, 0x00008000, 0x01808000);

    test_r_op!(test_zexth_24,  zext_h, 0x00007fff, 0x00007fff);
    test_r_op!(test_zexth_25,  zext_h, 0x0000ffff, 0x7fffffff);
    test_r_op!(test_zexth_26,  zext_h, 0x0000ffff, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Rotate Left (`rol`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/rol.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_rol_2,  rol, 0x00000001, 0x00000001, 0);
    test_rr_op!(test_rol_3,  rol, 0x00000002, 0x00000001, 1);
    test_rr_op!(test_rol_4,  rol, 0x00000080, 0x00000001, 7);
    test_rr_op!(test_rol_5,  rol, 0x00004000, 0x00000001, 14);
    test_rr_op!(test_rol_6,  rol, 0x80000000, 0x00000001, 31);

    test_rr_op!(test_rol_7,  rol, 0xffffffff, 0xffffffff, 0);
    test_rr_op!(test_rol_8,  rol, 0xffffffff, 0xffffffff, 1);
    test_rr_op!(test_rol_9,  rol, 0xffffffff, 0xffffffff, 7);
    test_rr_op!(test_rol_10, rol, 0xffffffff, 0xffffffff, 14);
    test_rr_op!(test_rol_11, rol, 0xffffffff, 0xffffffff, 31);

    test_rr_op!(test_rol_12, rol, 0x21212121, 0x21212121, 0);
    test_rr_op!(test_rol_13, rol, 0x42424242, 0x21212121, 1);
    test_rr_op!(test_rol_14, rol, 0x90909090, 0x21212121, 7);
    test_rr_op!(test_rol_15, rol, 0x48484848, 0x21212121, 14);
    test_rr_op!(test_rol_16, rol, 0x90909090, 0x21212121, 31);

    // Verify that rotates only use bottom five bits

    test_rr_op!(test_rol_17, rol, 0x21212121, 0x21212121, 0xffffffe0);
    test_rr_op!(test_rol_18, rol, 0x42424242, 0x21212121, 0xffffffe1);
    test_rr_op!(test_rol_19, rol, 0x90909090, 0x21212121, 0xffffffe7);
    test_rr_op!(test_rol_20, rol, 0x48484848, 0x21212121, 0xffffffee);
    test_rr_op!(test_rol_21, rol, 0x90909090, 0x21212121, 0xffffffff);

    // Verify that rotates ignore top 32 (using true 64-bit values)

    test_rr_op!(test_rol_44, rol, 0x12345678, 0x12345678, 0);
    test_rr_op!(test_rol_45, rol, 0x23456781, 0x12345678, 4);
    test_rr_op!(test_rol_46, rol, 0x92345678, 0x92345678, 0);
    test_rr_op!(test_rol_47, rol, 0x93456789, 0x99345678, 4);

    test_rr_src1_eq_dest!(test_rol_22, rol, 0x00000080, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_rol_23, rol, 0x00004000, 0x00000001, 14);
    test_rr_src12_eq_dest!(test_rol_24, rol, 24, 3);

    test_rr_dest_bypass!(test_rol_25, 0, rol, 0x00000080, 0x00000001, 7);
    test_rr_dest_bypass!(test_rol_26, 1, rol, 0x00004000, 0x00000001, 14);
    test_rr_dest_bypass!(test_rol_27, 2, rol, 0x80000000, 0x00000001, 31);

    test_rr_src12_bypass!(test_rol_28, 0, 0, rol, 0x00000080, 0x00000001, 7);
    test_rr_src12_bypass!(test_rol_29, 0, 1, rol, 0x00004000, 0x00000001, 14);
    test_rr_src12_bypass!(test_rol_30, 0, 2, rol, 0x80000000, 0x00000001, 31);
    test_rr_src12_bypass!(test_rol_31, 1, 0, rol, 0x00000080, 0x00000001, 7);
    test_rr_src12_bypass!(test_rol_32, 1, 1, rol, 0x00004000, 0x00000001, 14);
    test_rr_src12_bypass!(test_rol_33, 2, 0, rol, 0x80000000, 0x00000001, 31);

    test_rr_src21_bypass!(test_rol_34, 0, 0, rol, 0x00000080, 0x00000001, 7);
    test_rr_src21_bypass!(test_rol_35, 0, 1, rol, 0x00004000, 0x00000001, 14);
    test_rr_src21_bypass!(test_rol_36, 0, 2, rol, 0x80000000, 0x00000001, 31);
    test_rr_src21_bypass!(test_rol_37, 1, 0, rol, 0x00000080, 0x00000001, 7);
    test_rr_src21_bypass!(test_rol_38, 1, 1, rol, 0x00004000, 0x00000001, 14);
    test_rr_src21_bypass!(test_rol_39, 2, 0, rol, 0x80000000, 0x00000001, 31);

    test_rr_zerosrc1!(test_rol_40, rol, 0, 15);
    test_rr_zerosrc2!(test_rol_41, rol, 32, 32);
    test_rr_zerosrc12!(test_rol_42, rol, 0);
    test_rr_zerodest!(test_rol_43, rol, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Rotate Right (`ror`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/ror.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_ror_2,  ror, 0x00000001, 0x00000001, 0);
    test_rr_op!(test_ror_3,  ror, 0x80000000, 0x00000001, 1);
    test_rr_op!(test_ror_4,  ror, 0x02000000, 0x00000001, 7);
    test_rr_op!(test_ror_5,  ror, 0x00040000, 0x00000001, 14);
    test_rr_op!(test_ror_6,  ror, 0x00000002, 0x00000001, 31);

    test_rr_op!(test_ror_7,  ror, 0xffffffff, 0xffffffff, 0);
    test_rr_op!(test_ror_8,  ror, 0xffffffff, 0xffffffff, 1);
    test_rr_op!(test_ror_9,  ror, 0xffffffff, 0xffffffff, 7);
    test_rr_op!(test_ror_10, ror, 0xffffffff, 0xffffffff, 14);
    test_rr_op!(test_ror_11, ror, 0xffffffff, 0xffffffff, 31);

    test_rr_op!(test_ror_12, ror, 0x21212121, 0x21212121, 0);
    test_rr_op!(test_ror_13, ror, 0x90909090, 0x21212121, 1);
    test_rr_op!(test_ror_14, ror, 0x42424242, 0x21212121, 7);
    test_rr_op!(test_ror_15, ror, 0x84848484, 0x21212121, 14);
    test_rr_op!(test_ror_16, ror, 0x42424242, 0x21212121, 31);

    // Verify that shifts only use bottom six(rv64) or five(rv32) bits

    test_rr_op!(test_ror_17, ror, 0x21212121, 0x21212121, 0xffffffc0);
    test_rr_op!(test_ror_18, ror, 0x90909090, 0x21212121, 0xffffffc1);
    test_rr_op!(test_ror_19, ror, 0x42424242, 0x21212121, 0xffffffc7);
    test_rr_op!(test_ror_20, ror, 0x84848484, 0x21212121, 0xffffffce);

    test_rr_op!(test_ror_21, ror, 0x42424242, 0x21212121, 0xffffffff);

    test_rr_src1_eq_dest!(test_ror_22, ror, 0x02000000, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_ror_23, ror, 0x00040000, 0x00000001, 14);
    test_rr_src12_eq_dest!(test_ror_24, ror, 0x60000000, 3);

    test_rr_dest_bypass!(test_ror_25, 0, ror, 0x02000000, 0x00000001, 7);
    test_rr_dest_bypass!(test_ror_26, 1, ror, 0x00040000, 0x00000001, 14);
    test_rr_dest_bypass!(test_ror_27, 2, ror, 0x00000002, 0x00000001, 31);

    test_rr_src12_bypass!(test_ror_28, 0, 0, ror, 0x02000000, 0x00000001, 7);
    test_rr_src12_bypass!(test_ror_29, 0, 1, ror, 0x00040000, 0x00000001, 14);
    test_rr_src12_bypass!(test_ror_30, 0, 2, ror, 0x00000002, 0x00000001, 31);
    test_rr_src12_bypass!(test_ror_31, 1, 0, ror, 0x02000000, 0x00000001, 7);
    test_rr_src12_bypass!(test_ror_32, 1, 1, ror, 0x00040000, 0x00000001, 14);
    test_rr_src12_bypass!(test_ror_33, 2, 0, ror, 0x00000002, 0x00000001, 31);

    test_rr_src21_bypass!(test_ror_34, 0, 0, ror, 0x02000000, 0x00000001, 7);
    test_rr_src21_bypass!(test_ror_35, 0, 1, ror, 0x00040000, 0x00000001, 14);
    test_rr_src21_bypass!(test_ror_36, 0, 2, ror, 0x00000002, 0x00000001, 31);
    test_rr_src21_bypass!(test_ror_37, 1, 0, ror, 0x02000000, 0x00000001, 7);
    test_rr_src21_bypass!(test_ror_38, 1, 1, ror, 0x00040000, 0x00000001, 14);
    test_rr_src21_bypass!(test_ror_39, 2, 0, ror, 0x00000002, 0x00000001, 31);

    test_rr_zerosrc1!(test_ror_40, ror, 0, 15);
    test_rr_zerosrc2!(test_ror_41, ror, 32, 32);
    test_rr_zerosrc12!(test_ror_42, ror, 0);
    test_rr_zerodest!(test_ror_43, ror, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Rotate Right Immediate (`rori`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/rori.S
    // ---------------------------------------------------------------------------------------------

    test_imm_op!(test_rori_2,  rori, 0x00000001, 0x00000001, 0);
    test_imm_op!(test_rori_3,  rori, 0x80000000, 0x00000001, 1);
    test_imm_op!(test_rori_4,  rori, 0x02000000, 0x00000001, 7);
    test_imm_op!(test_rori_5,  rori, 0x00040000, 0x00000001, 14);
    test_imm_op!(test_rori_6,  rori, 0x00000002, 0x00000001, 31);

    test_imm_op!(test_rori_7,  rori, 0xffffffff, 0xffffffff, 0);
    test_imm_op!(test_rori_8,  rori, 0xffffffff, 0xffffffff, 1);
    test_imm_op!(test_rori_9,  rori, 0xffffffff, 0xffffffff, 7);
    test_imm_op!(test_rori_10, rori, 0xffffffff, 0xffffffff, 14);
    test_imm_op!(test_rori_11, rori, 0xffffffff, 0xffffffff, 31);

    test_imm_op!(test_rori_12, rori, 0x21212121, 0x21212121, 0);
    test_imm_op!(test_rori_13, rori, 0x90909090, 0x21212121, 1);
    test_imm_op!(test_rori_14, rori, 0x42424242, 0x21212121, 7);
    test_imm_op!(test_rori_15, rori, 0x84848484, 0x21212121, 14);
    test_imm_op!(test_rori_16, rori, 0x42424242, 0x21212121, 31);

    test_imm_src1_eq_dest!(test_rori_20, rori, 0x02000000, 0x00000001, 7);

    test_imm_dest_bypass!(test_rori_21, 0, rori, 0x02000000, 0x00000001, 7);
    test_imm_dest_bypass!(test_rori_22, 1, rori, 0x00040000, 0x00000001, 14);
    test_imm_dest_bypass!(test_rori_23, 2, rori, 0x00000002, 0x00000001, 31);

    test_imm_src1_bypass!(test_rori_24, 0, rori, 0x02000000, 0x00000001, 7);
    test_imm_src1_bypass!(test_rori_25, 1, rori, 0x00040000, 0x00000001, 14);
    test_imm_src1_bypass!(test_rori_26, 2, rori, 0x00000002, 0x00000001, 31);

    test_imm_zero_src1!(test_rori_27, rori, 0, 31);
    test_imm_zero_dest!(test_rori_28, rori, 33, 20);

    // ---------------------------------------------------------------------------------------------
    // Tests for Bitwise OR-Combine, byte granule (`orc.b`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/orc_b.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_orcb_2,  orc_b, 0x00000000, 0x00000000);
    test_r_op!(test_orcb_3,  orc_b, 0x000000ff, 0x00000001);
    test_r_op!(test_orcb_4,  orc_b, 0x000000ff, 0x00000003);

    test_r_op!(test_orcb_5,  orc_b, 0xffffff00, 0xffff8000);
    test_r_op!(test_orcb_6,  orc_b, 0x00ff0000, 0x00800000);
    test_r_op!(test_orcb_7,  orc_b, 0xffffff00, 0xffff8000);

    test_r_op!(test_orcb_8,  orc_b, 0x0000ffff, 0x00007fff);
    test_r_op!(test_orcb_9,  orc_b, 0xffffffff, 0x7fffffff);
    test_r_op!(test_orcb_10, orc_b, 0x00ffffff, 0x0007ffff);

    test_r_op!(test_orcb_11, orc_b, 0xff000000, 0x80000000);
    test_r_op!(test_orcb_12, orc_b, 0xffffff00, 0x121f5000);

    test_r_op!(test_orcb_13, orc_b, 0x00000000, 0x00000000);
    test_r_op!(test_orcb_14, orc_b, 0x000000ff, 0x0000000e);
    test_r_op!(test_orcb_15, orc_b, 0xffffffff, 0x20401341);

    test_r_src1_eq_dest!(test_orcb_16, orc_b, 0xff, 13);
    test_r_src1_eq_dest!(test_orcb_17, orc_b, 0xff, 11);

    test_r_dest_bypass!(test_orcb_18, 0, orc_b, 0xff, 13);
    test_r_dest_bypass!(test_orcb_29, 1, orc_b, 0xff, 19);
    test_r_dest_bypass!(test_orcb_20, 2, orc_b, 0xff, 34);

    test_r_op!(test_orcb_21,  orc_b, 0x00ffff00, 0x007f8000);
    test_r_op!(test_orcb_22,  orc_b, 0x00ffff00, 0x00808000);
    test_r_op!(test_orcb_23,  orc_b, 0xffffff00, 0x01808000);

    test_r_op!(test_orcb_24,  orc_b, 0x0000ffff, 0x00007fff);
    test_r_op!(test_orcb_25,  orc_b, 0xffffffff, 0x7fffffff);
    test_r_op!(test_orcb_26,  orc_b, 0x00ffffff, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Byte-reverse (`rev8`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/rev8.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_rev8_2,  rev8, 0x00000000, 0x00000000);
    test_r_op!(test_rev8_3,  rev8, 0x01000000, 0x00000001);
    test_r_op!(test_rev8_4,  rev8, 0x03000000, 0x00000003);

    test_r_op!(test_rev8_5,  rev8, 0x0080ffff, 0xffff8000);
    test_r_op!(test_rev8_6,  rev8, 0x00008000, 0x00800000);
    test_r_op!(test_rev8_7,  rev8, 0x0080ffff, 0xffff8000);

    test_r_op!(test_rev8_8,  rev8, 0xff7f0000, 0x00007fff);
    test_r_op!(test_rev8_9,  rev8, 0xffffff7f, 0x7fffffff);
    test_r_op!(test_rev8_10, rev8, 0xffff0700, 0x0007ffff);

    test_r_op!(test_rev8_11, rev8, 0x00000080, 0x80000000);
    test_r_op!(test_rev8_12, rev8, 0x00501f12, 0x121f5000);

    test_r_op!(test_rev8_13, rev8, 0x00000000, 0x00000000);
    test_r_op!(test_rev8_14, rev8, 0x0e000000, 0x0000000e);
    test_r_op!(test_rev8_15, rev8, 0x41134020, 0x20401341);

    test_r_src1_eq_dest!(test_rev8_16, rev8, 0x0d000000, 13);
    test_r_src1_eq_dest!(test_rev8_17, rev8, 0x0b000000, 11);

    test_r_dest_bypass!(test_rev8_18, 0, rev8, 0x0d000000, 13);
    test_r_dest_bypass!(test_rev8_29, 1, rev8, 0x13000000, 19);
    test_r_dest_bypass!(test_rev8_20, 2, rev8, 0x22000000, 34);

    test_r_op!(test_rev8_21,  rev8, 0x00807f00, 0x007f8000);
    test_r_op!(test_rev8_22,  rev8, 0x00808000, 0x00808000);
    test_r_op!(test_rev8_23,  rev8, 0x00808001, 0x01808000);

    test_r_op!(test_rev8_24,  rev8, 0xff7f0000, 0x00007fff);
    test_r_op!(test_rev8_25,  rev8, 0xffffff7f, 0x7fffffff);
    test_r_op!(test_rev8_26,  rev8, 0xffff0700, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Count leading zero bits (`clz`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/clz.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_clz_2,  clz, 32, 0x00000000);
    test_r_op!(test_clz_3,  clz, 31, 0x00000001);
    test_r_op!(test_clz_4,  clz, 30, 0x00000003);

    test_r_op!(test_clz_5,  clz, 0, 0xffff8000);
    test_r_op!(test_clz_6,  clz, 8, 0x00800000);
    test_r_op!(test_clz_7,  clz, 0, 0xffff8000);

    test_r_op!(test_clz_8,  clz, 17, 0x00007fff);
    test_r_op!(test_clz_9,  clz, 1, 0x7fffffff);
    test_r_op!(test_clz_10, clz, 13, 0x0007ffff);

    test_r_op!(test_clz_11, clz, 0, 0x80000000);
    test_r_op!(test_clz_12, clz, 3, 0x121f5000);

    test_r_op!(test_clz_13, clz, 5, 0x04000000);
    test_r_op!(test_clz_14, clz, 28, 0x0000000e);
    test_r_op!(test_clz_15, clz, 2, 0x20401341);

    test_r_src1_eq_dest!(test_clz_16, clz, 28, 13);
    test_r_src1_eq_dest!(test_clz_17, clz, 28, 11);

    test_r_dest_bypass!(test_clz_18, 0, clz, 28, 13);
    test_r_dest_bypass!(test_clz_29, 1, clz, 27, 19);
    test_r_dest_bypass!(test_clz_20, 2, clz, 26, 34);

    test_r_op!(test_clz_21, clz, 5, 0x070f8000);
    test_r_op!(test_clz_22, clz, 4, 0x08008000);
    test_r_op!(test_clz_23, clz, 3, 0x18008000);

    test_r_op!(test_clz_24, clz, 17, 0x00007fff);
    test_r_op!(test_clz_25, clz, 1, 0x7fffffff);
    test_r_op!(test_clz_26, clz, 13, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Count trailing zero bits (`ctz`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/ctz.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_ctz_2,  ctz, 32, 0x00000000);
    test_r_op!(test_ctz_3,  ctz, 0, 0x00000001);
    test_r_op!(test_ctz_4,  ctz, 0, 0x00000003);

    test_r_op!(test_ctz_5,  ctz, 15, 0xffff8000);
    test_r_op!(test_ctz_6,  ctz, 23, 0x00800000);
    test_r_op!(test_ctz_7,  ctz, 15, 0xffff8000);

    test_r_op!(test_ctz_8,  ctz, 0, 0x00007fff);
    test_r_op!(test_ctz_9,  ctz, 0, 0x7fffffff);
    test_r_op!(test_ctz_10, ctz, 0, 0x0007ffff);

    test_r_op!(test_ctz_11, ctz, 31, 0x80000000);
    test_r_op!(test_ctz_12, ctz, 12, 0x121f5000);

    test_r_op!(test_ctz_13, ctz, 30, 0xc0000000);
    test_r_op!(test_ctz_14, ctz, 1, 0x0000000e);
    test_r_op!(test_ctz_15, ctz, 0, 0x20401341);

    test_r_src1_eq_dest!(test_ctz_16, ctz, 0, 13);
    test_r_src1_eq_dest!(test_ctz_17, ctz, 0, 11);

    test_r_dest_bypass!(test_ctz_18, 0, ctz, 0, 13);
    test_r_dest_bypass!(test_ctz_29, 1, ctz, 0, 19);
    test_r_dest_bypass!(test_ctz_20, 2, ctz, 1, 34);

    test_r_op!(test_ctz_21,  ctz, 15, 0x007f8000);
    test_r_op!(test_ctz_22,  ctz, 15, 0x00808000);
    test_r_op!(test_ctz_23,  ctz, 12, 0x01809000);

    test_r_op!(test_ctz_24,  ctz, 0, 0x00007fff);
    test_r_op!(test_ctz_25,  ctz, 0, 0x7fffffff);
    test_r_op!(test_ctz_26,  ctz, 0, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Count set bits (`cpop`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbb/cpop.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_cpop_2,  cpop, 0, 0x00000000);
    test_r_op!(test_cpop_3,  cpop, 1, 0x00000001);
    test_r_op!(test_cpop_4,  cpop, 2, 0x00000003);

    test_r_op!(test_cpop_5,  cpop, 17, 0xffff8000);
    test_r_op!(test_cpop_6,  cpop, 1, 0x00800000);
    test_r_op!(test_cpop_7,  cpop, 18, 0xffff6000);

    test_r_op!(test_cpop_8,  cpop, 15, 0x00007fff);
    test_r_op!(test_cpop_9,  cpop, 31, 0x7fffffff);
    test_r_op!(test_cpop_10, cpop, 19, 0x0007ffff);

    test_r_op!(test_cpop_11, cpop, 1, 0x80000000);
    test_r_op!(test_cpop_12, cpop, 9, 0x121f5000);

    test_r_op!(test_cpop_13, cpop, 0, 0x00000000);
    test_r_op!(test_cpop_14, cpop, 3, 0x0000000e);
    test_r_op!(test_cpop_15, cpop, 7, 0x20401341);

    test_r_src1_eq_dest!(test_cpop_16, cpop, 3, 13);
    test_r_src1_eq_dest!(test_cpop_17, cpop, 3, 11);

    test_r_dest_bypass!(test_cpop_18, 0, cpop, 3, 13);
    test_r_dest_bypass!(test_cpop_29, 1, cpop, 3, 19);
    test_r_dest_bypass!(test_cpop_20, 2, cpop, 2, 34);

    test_r_op!(test_cpop_21,  cpop, 8, 0x007f8000);
    test_r_op!(test_cpop_22,  cpop, 2, 0x00808000);
    test_r_op!(test_cpop_23,  cpop, 3, 0x01808000);

    test_r_op!(test_cpop_24,  cpop, 17, 0x30007fff);
    test_r_op!(test_cpop_25,  cpop, 30, 0x77ffffff);
    test_r_op!(test_cpop_26,  cpop, 19, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Sign-extend byte (`sext.b`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/sext_b.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_sext_b_2,  sext_b, 0x00000000, 0x00000000);
    test_r_op!(test_sext_b_3,  sext_b, 0x00000001, 0x00000001);
    test_r_op!(test_sext_b_4,  sext_b, 0x00000003, 0x00000003);

    test_r_op!(test_sext_b_5,  sext_b, 0x00000000, 0xffff8000);
    test_r_op!(test_sext_b_6,  sext_b, 0x00000000, 0x00800000);
    test_r_op!(test_sext_b_7,  sext_b, 0x00000000, 0xffff8000);

    test_r_op!(test_sext_b_8,  sext_b, 0xffffffff, 0x00007fff);
    test_r_op!(test_sext_b_9,  sext_b, 0xffffffff, 0x7fffffff);
    test_r_op!(test_sext_b_10, sext_b, 0xffffffff, 0x0007ffff);

    test_r_op!(test_sext_b_11, sext_b, 0x00000000, 0x80000000);
    test_r_op!(test_sext_b_12, sext_b, 0x00000000, 0x121f5000);

    test_r_op!(test_sext_b_13, sext_b, 0x00000000, 0x00000000);
    test_r_op!(test_sext_b_14, sext_b, 0x0000000e, 0x0000000e);
    test_r_op!(test_sext_b_15, sext_b, 0x00000041, 0x20401341);

    test_r_src1_eq_dest!(test_sext_b_16, sext_b, 0x0000000d, 13);
    test_r_src1_eq_dest!(test_sext_b_17, sext_b, 0x0000000b, 11);

    test_r_dest_bypass!(test_sext_b_18, 0, sext_b, 0x0000000d, 13);
    test_r_dest_bypass!(test_sext_b_29, 1, sext_b, 0x00000013, 19);
    test_r_dest_bypass!(test_sext_b_20, 2, sext_b, 0x00000022, 34);

    test_r_op!(test_sext_b_21,  sext_b, 0x00000000, 0x007f8000);
    test_r_op!(test_sext_b_22,  sext_b, 0x00000000, 0x00808000);
    test_r_op!(test_sext_b_23,  sext_b, 0x00000000, 0x01808000);

    test_r_op!(test_sext_b_24,  sext_b, 0xffffffff, 0x00007fff);
    test_r_op!(test_sext_b_25,  sext_b, 0xffffffff, 0x7fffffff);
    test_r_op!(test_sext_b_26,  sext_b, 0xffffffff, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Sign-extend halfword (`sext.h`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbb/sext_h.S
    // ---------------------------------------------------------------------------------------------

    test_r_op!(test_sext_h_2,  sext_h, 0x00000000, 0x00000000);
    test_r_op!(test_sext_h_3,  sext_h, 0x00000001, 0x00000001);
    test_r_op!(test_sext_h_4,  sext_h, 0x00000003, 0x00000003);

    test_r_op!(test_sext_h_5,  sext_h, 0xffff8000, 0xffff8000);
    test_r_op!(test_sext_h_6,  sext_h, 0x00000000, 0x00800000);
    test_r_op!(test_sext_h_7,  sext_h, 0xffff8000, 0xffff8000);

    test_r_op!(test_sext_h_8,  sext_h, 0x00007fff, 0x00007fff);
    test_r_op!(test_sext_h_9,  sext_h, 0xffffffff, 0x7fffffff);
    test_r_op!(test_sext_h_10, sext_h, 0xffffffff, 0x0007ffff);

    test_r_op!(test_sext_h_11, sext_h, 0x00000000, 0x80000000);
    test_r_op!(test_sext_h_12, sext_h, 0x00005000, 0x121f5000);

    test_r_op!(test_sext_h_13, sext_h, 0x00000000, 0x00000000);
    test_r_op!(test_sext_h_14, sext_h, 0x0000000e, 0x0000000e);
    test_r_op!(test_sext_h_15, sext_h, 0x00001341, 0x20401341);

    test_r_src1_eq_dest!(test_sext_h_16, sext_h, 0x0000000d, 13);
    test_r_src1_eq_dest!(test_sext_h_17, sext_h, 0x0000000b, 11);

    test_r_dest_bypass!(test_sext_h_18, 0, sext_h, 0x0000000d, 13);
    test_r_dest_bypass!(test_sext_h_29, 1, sext_h, 0x00000013, 19);
    test_r_dest_bypass!(test_sext_h_20, 2, sext_h, 0x00000022, 34);

    test_r_op!(test_sext_h_21,  sext_h, 0xffff8000, 0x007f8000);
    test_r_op!(test_sext_h_22,  sext_h, 0xffff8000, 0x00808000);
    test_r_op!(test_sext_h_23,  sext_h, 0xffff8000, 0x01808000);

    test_r_op!(test_sext_h_24,  sext_h, 0x00007fff, 0x00007fff);
    test_r_op!(test_sext_h_25,  sext_h, 0xffffffff, 0x7fffffff);
    test_r_op!(test_sext_h_26,  sext_h, 0xffffffff, 0x0007ffff);

    // ---------------------------------------------------------------------------------------------
    // Tests for Singe-bit invert (`binv`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/binv.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_binv_2,  binv, 0x00000000, 0x00000001, 0);
    test_rr_op!(test_binv_3,  binv, 0x00000003, 0x00000001, 1);
    test_rr_op!(test_binv_4,  binv, 0x00000081, 0x00000001, 7);
    test_rr_op!(test_binv_5,  binv, 0x00004001, 0x00000001, 14);
    test_rr_op!(test_binv_6,  binv, 0x80000001, 0x00000001, 31);

    test_rr_op!(test_binv_7,  binv, 0xfffffffe, 0xffffffff, 0);
    test_rr_op!(test_binv_8,  binv, 0xfffffffd, 0xffffffff, 1);
    test_rr_op!(test_binv_9,  binv, 0xffffff7f, 0xffffffff, 7);
    test_rr_op!(test_binv_10, binv, 0xffffbfff, 0xffffffff, 14);
    test_rr_op!(test_binv_11, binv, 0x7fffffff, 0xffffffff, 31);

    test_rr_op!(test_binv_12, binv, 0x21212120, 0x21212121, 0);
    test_rr_op!(test_binv_13, binv, 0x21212123, 0x21212121, 1);
    test_rr_op!(test_binv_14, binv, 0x212121a1, 0x21212121, 7);
    test_rr_op!(test_binv_15, binv, 0x21216121, 0x21212121, 14);
    test_rr_op!(test_binv_16, binv, 0xa1212121, 0x21212121, 31);

    // Verify that shifts only use bottom six(rv64) or five(rv32) bits

    test_rr_op!(test_binv_17, binv, 0x21212120, 0x21212121, 0xffffffc0);
    test_rr_op!(test_binv_18, binv, 0x21212123, 0x21212121, 0xffffffc1);
    test_rr_op!(test_binv_19, binv, 0x212121a1, 0x21212121, 0xffffffc7);
    test_rr_op!(test_binv_20, binv, 0x21216121, 0x21212121, 0xffffffce);

    test_rr_src1_eq_dest!(test_binv_22, binv, 0x00000081, 0x00000001, 7);
    test_rr_src2_eq_dest!(test_binv_23, binv, 0x00004001, 0x00000001, 14);
    test_rr_src12_eq_dest!(test_binv_24, binv, 11, 3);

    test_rr_dest_bypass!(test_binv_25, 0, binv, 0x00000081, 0x00000001, 7);
    test_rr_dest_bypass!(test_binv_26, 1, binv, 0x00004001, 0x00000001, 14);
    test_rr_dest_bypass!(test_binv_27, 2, binv, 0x80000001, 0x00000001, 31);

    test_rr_src12_bypass!(test_binv_28, 0, 0, binv, 0x00000081, 0x00000001, 7);
    test_rr_src12_bypass!(test_binv_29, 0, 1, binv, 0x00004001, 0x00000001, 14);
    test_rr_src12_bypass!(test_binv_30, 0, 2, binv, 0x80000001, 0x00000001, 31);
    test_rr_src12_bypass!(test_binv_31, 1, 0, binv, 0x00000081, 0x00000001, 7);
    test_rr_src12_bypass!(test_binv_32, 1, 1, binv, 0x00004001, 0x00000001, 14);
    test_rr_src12_bypass!(test_binv_33, 2, 0, binv, 0x80000001, 0x00000001, 31);

    test_rr_src21_bypass!(test_binv_34, 0, 0, binv, 0x00000081, 0x00000001, 7);
    test_rr_src21_bypass!(test_binv_35, 0, 1, binv, 0x00004001, 0x00000001, 14);
    test_rr_src21_bypass!(test_binv_36, 0, 2, binv, 0x80000001, 0x00000001, 31);
    test_rr_src21_bypass!(test_binv_37, 1, 0, binv, 0x00000081, 0x00000001, 7);
    test_rr_src21_bypass!(test_binv_38, 1, 1, binv, 0x00004001, 0x00000001, 14);
    test_rr_src21_bypass!(test_binv_39, 2, 0, binv, 0x80000001, 0x00000001, 31);

    test_rr_zerosrc1!(test_binv_40, binv, 0x00008000, 15);
    test_rr_zerosrc2!(test_binv_41, binv, 33, 32);
    test_rr_zerosrc12!(test_binv_42, binv, 1);
    test_rr_zerodest!(test_binv_43, binv, 1024, 2048);

    // ---------------------------------------------------------------------------------------------
    // Tests for Singe-bit invert immediate (`binvi`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv64uzbs/binvi.S
    // ---------------------------------------------------------------------------------------------

    test_imm_op!(test_binvi_2,  binvi, 0x00000000, 0x00000001, 0);
    test_imm_op!(test_binvi_3,  binvi, 0x00000003, 0x00000001, 1);
    test_imm_op!(test_binvi_4,  binvi, 0x00000081, 0x00000001, 7);
    test_imm_op!(test_binvi_5,  binvi, 0x00004001, 0x00000001, 14);
    test_imm_op!(test_binvi_6,  binvi, 0x80000001, 0x00000001, 31);

    test_imm_op!(test_binvi_7,  binvi, 0xfffffffe, 0xffffffff, 0);
    test_imm_op!(test_binvi_8,  binvi, 0xfffffffd, 0xffffffff, 1);
    test_imm_op!(test_binvi_9,  binvi, 0xffffff7f, 0xffffffff, 7);
    test_imm_op!(test_binvi_10, binvi, 0xffffbfff, 0xffffffff, 14);
    test_imm_op!(test_binvi_11, binvi, 0x7fffffff, 0xffffffff, 31);

    test_imm_op!(test_binvi_12, binvi, 0x21212120, 0x21212121, 0);
    test_imm_op!(test_binvi_13, binvi, 0x21212123, 0x21212121, 1);
    test_imm_op!(test_binvi_14, binvi, 0x212121a1, 0x21212121, 7);
    test_imm_op!(test_binvi_15, binvi, 0x21216121, 0x21212121, 14);
    test_imm_op!(test_binvi_16, binvi, 0xa1212121, 0x21212121, 31);

    test_imm_src1_eq_dest!(test_binvi_17, binvi, 0x00000081, 0x00000001, 7);

    test_imm_dest_bypass!(test_binvi_18, 0, binvi, 0x00000081, 0x00000001, 7);
    test_imm_dest_bypass!(test_binvi_19, 1, binvi, 0x00004001, 0x00000001, 14);
    test_imm_dest_bypass!(test_binvi_20, 2, binvi, 0x80000001, 0x00000001, 31);

    test_imm_src1_bypass!(test_binvi_21, 0, binvi, 0x00000081, 0x00000001, 7);
    test_imm_src1_bypass!(test_binvi_22, 1, binvi, 0x00004001, 0x00000001, 14);
    test_imm_src1_bypass!(test_binvi_23, 2, binvi, 0x80000001, 0x00000001, 31);

    test_imm_zero_src1!(test_binvi_24, binvi, 0x00008000, 15);
    test_imm_zero_dest!(test_binvi_25, binvi, 1024, 10);

    // ---------------------------------------------------------------------------------------------
    // Tests for Carry-less multiply low-part (`clmul`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbc/clmul.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_clmul_32,  clmul, 0x00005a00, 0x00007e00, 0xb6db6db7);
    test_rr_op!(test_clmul_33,  clmul, 0x00005b40, 0x00007fc0, 0xb6db6db7);

    test_rr_op!(test_clmul_2,  clmul, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_clmul_3,  clmul, 0x00000001, 0x00000001, 0x00000001);
    test_rr_op!(test_clmul_4,  clmul, 0x00000009, 0x00000003, 0x00000007);

    test_rr_op!(test_clmul_5,  clmul, 0x00000000, 0x00000000, 0xffff8000);
    test_rr_op!(test_clmul_6,  clmul, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_clmul_7,  clmul, 0x00000000, 0x80000000, 0xffff8000);

    test_rr_op!(test_clmul_30,  clmul, 0xfffc324f, 0xaaaaaaab, 0x0002fe7d);
    test_rr_op!(test_clmul_31,  clmul, 0xfffc324f, 0x0002fe7d, 0xaaaaaaab);

    test_rr_op!(test_clmul_34,  clmul, 0x00000000, 0xff000000, 0xff000000);

    test_rr_op!(test_clmul_35,  clmul, 0x55555555, 0xffffffff, 0xffffffff);
    test_rr_op!(test_clmul_36,  clmul, 0xffffffff, 0xffffffff, 0x00000001);
    test_rr_op!(test_clmul_37,  clmul, 0xffffffff, 0x00000001, 0xffffffff);

    test_rr_src1_eq_dest!(test_clmul_8, clmul, 0x7f, 13, 11);
    test_rr_src2_eq_dest!(test_clmul_9, clmul, 0x62, 14, 11);
    test_rr_src12_eq_dest!(test_clmul_10, clmul, 0x51, 13);

    test_rr_dest_bypass!(test_clmul_11, 0, clmul, 0x7f, 13, 11);
    test_rr_dest_bypass!(test_clmul_12, 1, clmul, 0x62, 14, 11);
    test_rr_dest_bypass!(test_clmul_13, 2, clmul, 0x69, 15, 11);

    test_rr_src12_bypass!(test_clmul_14, 0, 0, clmul, 0x7f, 13, 11);
    test_rr_src12_bypass!(test_clmul_15, 0, 1, clmul, 0x62, 14, 11);
    test_rr_src12_bypass!(test_clmul_16, 0, 2, clmul, 0x69, 15, 11);
    test_rr_src12_bypass!(test_clmul_17, 1, 0, clmul, 0x7f, 13, 11);
    test_rr_src12_bypass!(test_clmul_18, 1, 1, clmul, 0x62, 14, 11);
    test_rr_src12_bypass!(test_clmul_19, 2, 0, clmul, 0x69, 15, 11);

    test_rr_src21_bypass!(test_clmul_20, 0, 0, clmul, 0x7f, 13, 11);
    test_rr_src21_bypass!(test_clmul_21, 0, 1, clmul, 0x62, 14, 11);
    test_rr_src21_bypass!(test_clmul_22, 0, 2, clmul, 0x69, 15, 11);
    test_rr_src21_bypass!(test_clmul_23, 1, 0, clmul, 0x7f, 13, 11);
    test_rr_src21_bypass!(test_clmul_24, 1, 1, clmul, 0x62, 14, 11);
    test_rr_src21_bypass!(test_clmul_25, 2, 0, clmul, 0x69, 15, 11);

    test_rr_zerosrc1!(test_clmul_26, clmul, 0, 31);
    test_rr_zerosrc2!(test_clmul_27, clmul, 0, 32);
    test_rr_zerosrc12!(test_clmul_28, clmul, 0);
    test_rr_zerodest!(test_clmul_29, clmul, 33, 34);

    // ---------------------------------------------------------------------------------------------
    // Tests for Carry-less multiply high-part (`clmulh`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbc/clmulh.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_clmulh_32,  clmulh, 0x00003600, 0x00007e00, 0xb6db6db7);
    test_rr_op!(test_clmulh_33,  clmulh, 0x000036c0, 0x00007fc0, 0xb6db6db7);

    test_rr_op!(test_clmulh_2,  clmulh, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_clmulh_3,  clmulh, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_clmulh_4,  clmulh, 0x00000000, 0x00000003, 0x00000007);

    test_rr_op!(test_clmulh_5,  clmulh, 0x00000000, 0x00000000, 0xffff8000);
    test_rr_op!(test_clmulh_6,  clmulh, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_clmulh_7,  clmulh, 0x7fffc000, 0x80000000, 0xffff8000);

    test_rr_op!(test_clmulh_30,  clmulh, 0x000133cd, 0xaaaaaaab, 0x0002fe7d);
    test_rr_op!(test_clmulh_31,  clmulh, 0x000133cd, 0x0002fe7d, 0xaaaaaaab);

    test_rr_op!(test_clmulh_34,  clmulh, 0x55550000, 0xff000000, 0xff000000);

    test_rr_op!(test_clmulh_35,  clmulh, 0x55555555, 0xffffffff, 0xffffffff);
    test_rr_op!(test_clmulh_36,  clmulh, 0x00000000, 0xffffffff, 0x00000001);
    test_rr_op!(test_clmulh_37,  clmulh, 0x00000000, 0x00000001, 0xffffffff);

    test_rr_src1_eq_dest!(test_clmulh_8, clmulh, 0, 13, 11);
    test_rr_src2_eq_dest!(test_clmulh_9, clmulh, 0, 14, 11);
    test_rr_src12_eq_dest!(test_clmulh_10, clmulh, 0, 13);

    test_rr_dest_bypass!(test_clmulh_11, 0, clmulh, 0, 13, 11);
    test_rr_dest_bypass!(test_clmulh_12, 1, clmulh, 0, 14, 11);
    test_rr_dest_bypass!(test_clmulh_13, 2, clmulh, 0, 15, 11);

    test_rr_src12_bypass!(test_clmulh_14, 0, 0, clmulh, 0, 13, 11);
    test_rr_src12_bypass!(test_clmulh_15, 0, 1, clmulh, 0, 14, 11);
    test_rr_src12_bypass!(test_clmulh_16, 0, 2, clmulh, 0, 15, 11);
    test_rr_src12_bypass!(test_clmulh_17, 1, 0, clmulh, 0, 13, 11);
    test_rr_src12_bypass!(test_clmulh_18, 1, 1, clmulh, 0, 14, 11);
    test_rr_src12_bypass!(test_clmulh_19, 2, 0, clmulh, 0, 15, 11);

    test_rr_src21_bypass!(test_clmulh_20, 0, 0, clmulh, 0, 13, 11);
    test_rr_src21_bypass!(test_clmulh_21, 0, 1, clmulh, 0, 14, 11);
    test_rr_src21_bypass!(test_clmulh_22, 0, 2, clmulh, 0, 15, 11);
    test_rr_src21_bypass!(test_clmulh_23, 1, 0, clmulh, 0, 13, 11);
    test_rr_src21_bypass!(test_clmulh_24, 1, 1, clmulh, 0, 14, 11);
    test_rr_src21_bypass!(test_clmulh_25, 2, 0, clmulh, 0, 15, 11);

    test_rr_zerosrc1!(test_clmulh_26, clmulh, 0, 31);
    test_rr_zerosrc2!(test_clmulh_27, clmulh, 0, 32);
    test_rr_zerosrc12!(test_clmulh_28, clmulh, 0);
    test_rr_zerodest!(test_clmulh_29, clmulh, 33, 34);

    // ---------------------------------------------------------------------------------------------
    // Tests for Carry-less multiply reversed (`clmulr`) Instruction
    //
    // Test suite based on riscv-tests
    // https://github.com/riscv-software-src/riscv-tests/blob/master/isa/rv32uzbc/clmulr.S
    // ---------------------------------------------------------------------------------------------

    test_rr_op!(test_clmulr_32,  clmulr, 0x00006c00, 0x00007e00, 0xb6db6db7);
    test_rr_op!(test_clmulr_33,  clmulr, 0x00006d80, 0x00007fc0, 0xb6db6db7);

    test_rr_op!(test_clmulr_2,  clmulr, 0x00000000, 0x00000000, 0x00000000);
    test_rr_op!(test_clmulr_3,  clmulr, 0x00000000, 0x00000001, 0x00000001);
    test_rr_op!(test_clmulr_4,  clmulr, 0x00000000, 0x00000003, 0x00000007);

    test_rr_op!(test_clmulr_5,  clmulr, 0x00000000, 0x00000000, 0xffff8000);
    test_rr_op!(test_clmulr_6,  clmulr, 0x00000000, 0x80000000, 0x00000000);
    test_rr_op!(test_clmulr_7,  clmulr, 0xffff8000, 0x80000000, 0xffff8000);

    test_rr_op!(test_clmulr_30,  clmulr, 0x0002679b, 0xaaaaaaab, 0x0002fe7d);
    test_rr_op!(test_clmulr_31,  clmulr, 0x0002679b, 0x0002fe7d, 0xaaaaaaab);

    test_rr_op!(test_clmulr_34,  clmulr, 0xaaaa0000, 0xff000000, 0xff000000);

    test_rr_op!(test_clmulr_35,  clmulr, 0xaaaaaaaa, 0xffffffff, 0xffffffff);
    test_rr_op!(test_clmulr_36,  clmulr, 0x00000001, 0xffffffff, 0x00000001);
    test_rr_op!(test_clmulr_37,  clmulr, 0x00000001, 0x00000001, 0xffffffff);

    test_rr_src1_eq_dest!(test_clmulr_8, clmulr, 0, 13, 11);
    test_rr_src2_eq_dest!(test_clmulr_9, clmulr, 0, 14, 11);
    test_rr_src12_eq_dest!(test_clmulr_10, clmulr, 0, 13);

    test_rr_dest_bypass!(test_clmulr_11, 0, clmulr, 0, 13, 11);
    test_rr_dest_bypass!(test_clmulr_12, 1, clmulr, 0, 14, 11);
    test_rr_dest_bypass!(test_clmulr_13, 2, clmulr, 0, 15, 11);

    test_rr_src12_bypass!(test_clmulr_14, 0, 0, clmulr, 0, 13, 11);
    test_rr_src12_bypass!(test_clmulr_15, 0, 1, clmulr, 0, 14, 11);
    test_rr_src12_bypass!(test_clmulr_16, 0, 2, clmulr, 0, 15, 11);
    test_rr_src12_bypass!(test_clmulr_17, 1, 0, clmulr, 0, 13, 11);
    test_rr_src12_bypass!(test_clmulr_18, 1, 1, clmulr, 0, 14, 11);
    test_rr_src12_bypass!(test_clmulr_19, 2, 0, clmulr, 0, 15, 11);

    test_rr_src21_bypass!(test_clmulr_20, 0, 0, clmulr, 0, 13, 11);
    test_rr_src21_bypass!(test_clmulr_21, 0, 1, clmulr, 0, 14, 11);
    test_rr_src21_bypass!(test_clmulr_22, 0, 2, clmulr, 0, 15, 11);
    test_rr_src21_bypass!(test_clmulr_23, 1, 0, clmulr, 0, 13, 11);
    test_rr_src21_bypass!(test_clmulr_24, 1, 1, clmulr, 0, 14, 11);
    test_rr_src21_bypass!(test_clmulr_25, 2, 0, clmulr, 0, 15, 11);

    test_rr_zerosrc1!(test_clmulr_26, clmulr, 0, 31);
    test_rr_zerosrc2!(test_clmulr_27, clmulr, 0, 32);
    test_rr_zerosrc12!(test_clmulr_28, clmulr, 0);
    test_rr_zerodest!(test_clmulr_29, clmulr, 33, 34);
}
