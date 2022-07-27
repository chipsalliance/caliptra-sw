/*++

Licensed under the Apache-2.0 license.

File Name:

    jalr.rs

Abstract:

    File contains implementation of Jump and Link register instructions.

--*/

use crate::cpu::{Cpu, InstrTracer};
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{RvInstr, RvInstr32I, RvInstr32Opcode};

impl Cpu {
    /// Execute `jalr` Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_jalr_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Jalr);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::IType(instr));

        // Calculate the new program counter
        let pc = self.read_xreg(instr.rs())? as i32;
        let pc = pc.wrapping_add(instr.imm());
        let pc = pc as u32 & !1u32;
        let pc = pc.wrapping_sub(4);

        // Calculate the return address
        let lr = self.read_pc().wrapping_add(4);

        // Update the registers
        self.write_pc(pc);
        self.write_xreg(instr.rd(), lr)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{jalr, nop};
    use crate::xreg_file::XReg;
    use crate::{isa_test, text};

    #[test]
    fn test_jalr_2() {
        isa_test!(
            0x0000 => text![
                jalr(XReg::X1, XReg::X2, 0x0000);
                nop();
                nop();
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = 0x0008;
            },
            {
                XReg::X1 = 0x0004;
            }
        );
    }

    #[test]
    fn test_jalr_3() {
        isa_test!(
            0x0000 => text![
                jalr(XReg::X1, XReg::X1, 0x0000);
                nop();
                nop();
            ],
            0x1000 => vec![0],
            {
                XReg::X1 = 0x0008;
            },
            {
                XReg::X1 = 0x0004;
            }
        );
    }
}
