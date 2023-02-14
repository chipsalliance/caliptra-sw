/*++

Licensed under the Apache-2.0 license.

File Name:

    auipc.rs

Abstract:

    File contains implementation of Add Upper Immediate to Program Counter (`auipc`) instruction.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32Opcode, RvInstr32U};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvData, RvException};
use std::ops::Shl;

impl<TBus: Bus> Cpu<TBus> {
    /// Execute `auipc` Instruction
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_auipc_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32U(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Auipc);

        // Calculate value
        let imm = instr.imm().shl(12) as RvData;
        let val = self.read_pc().wrapping_add(imm) as RvData;

        // Save the contents to register
        self.write_xreg(instr.rd(), val)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{auipc, nop};
    use crate::xreg_file::XReg;
    use crate::{isa_test, text};

    #[test]
    fn test_auipc_2() {
        isa_test!(
            0x0000 => text![
                nop();
                auipc(XReg::X10, 10000);
            ],
            0x1000 => vec![0],
            {},
            {
                XReg::X10 = (10000 << 12) + 4;
            }
        );
    }

    #[test]
    fn test_auipc_3() {
        isa_test!(
            0x0000 => text![
                nop();
                auipc(XReg::X10, -10000);
            ],
            0x1000 => vec![0],
            {},
            {
                XReg::X10 = ((-10000i32 as u32) << 12) + 4;
            }
        );
    }
}
