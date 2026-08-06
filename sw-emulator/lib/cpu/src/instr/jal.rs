/*++

Licensed under the Apache-2.0 license.

File Name:

    jal.rs

Abstract:

    File contains implementation of Jump and Link instructions.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32J, RvInstr32Opcode};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvException;

impl<TBus: Bus> Cpu<TBus> {
    /// Execute `jal` Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_jal_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32J(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Jal);

        // Calculate the new program counter
        let next_pc = self.read_pc().wrapping_add(instr.imm());

        if let Some(sampler) = self.stack_sampler.as_mut() {
            if instr.rd().is_ra() || instr.rd().is_link() {
                sampler.record_call(next_pc);
            }
        }

        // Calculate the return address
        let lr = self.next_pc();

        // Update the registers
        self.set_next_pc(next_pc);
        self.write_xreg(instr.rd(), lr)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{addi, jal, nop};
    use crate::xreg_file::XReg;
    use crate::{isa_test, isa_test_cpu, text, StackSampler};

    #[test]
    fn test_jal_2() {
        isa_test!(
            0x0000 => text![
                jal(XReg::X1, 0x0008);
                nop();
                addi(XReg::X2, XReg::X0, 1);
                nop();
            ],
            0x1000 => vec![0],
            {
            },
            {
                XReg::X2 = 0x0001;
                XReg::X1 = 0x0004;
            }
        );
    }

    #[test]
    fn test_jal_record_call() {
        let text_base = 0u32;
        let text = text![
            jal(XReg::X1, 0x0008); // 0x0000, 1) Go to 0x0008, save 0x0004 in X1
            nop();                 // 0x0004
            jal(XReg::X5, 0x0008); // 0x0008, 2) Go to 0x0010, save 0x000c in X5
            nop();                 // 0x000c
            jal(XReg::X1, 0x0008); // 0x0010, 3) Go to 0x0018, save 0x0014 in X1
            nop();                 // 0x0014
        ];
        let mut cpu = isa_test_cpu!(
            text_base => text,
            0x1000 => vec![0]
        );
        // Sample the stack after each instruction.
        cpu.stack_sampler = Some(StackSampler::new(Some(1)));

        while cpu.read_pc() < text_base + text.len() as u32 {
            cpu.step(None);
        }

        let s = cpu.stack_sampler.as_ref().unwrap();
        assert_eq!(s.samples.get(&vec![0x0008]), Some(&1));
        assert_eq!(s.samples.get(&vec![0x0008, 0x0010]), Some(&1));
        assert_eq!(s.samples.get(&vec![0x0008, 0x0010, 0x0018]), Some(&1));
    }
}
