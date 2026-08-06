/*++

Licensed under the Apache-2.0 license.

File Name:

    jalr.rs

Abstract:

    File contains implementation of Jump and Link register instructions.

--*/

use crate::cpu::Cpu;
use crate::types::{RvInstr32I, RvInstr32Opcode};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::RvException;

impl<TBus: Bus> Cpu<TBus> {
    /// Execute `jalr` Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_jalr_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::Jalr);

        // Calculate the new program counter
        let pc = self.read_xreg(instr.rs())? as i32;
        let pc = pc.wrapping_add(instr.imm());
        let pc = pc as u32 & !1u32;

        if let Some(sampler) = self.stack_sampler.as_mut() {
            let rd = instr.rd().is_ra() || instr.rd().is_link();
            let rs = instr.rs().is_ra() || instr.rs().is_link();
            // Mimic the behavior of return-address stack (RAS) actions documented at
            // https://docs.riscv.org/reference/isa/v20260120/unpriv/rv32.html#rashints
            match (rd, rs) {
                (false, true) => sampler.record_ret(),
                (true, false) => sampler.record_call(pc),
                (true, true) if instr.rd() != instr.rs() => {
                    sampler.record_ret();
                    sampler.record_call(pc);
                }
                (true, true) if instr.rd() == instr.rs() => {
                    sampler.record_call(pc);
                }
                _ => (),
            }
        }

        // Calculate the return address
        let lr = self.next_pc();

        // Update the registers
        self.set_next_pc(pc);
        self.write_xreg(instr.rd(), lr)
    }
}

#[cfg(test)]
mod tests {
    use crate::instr::test_encoder::tests::{jalr, nop};
    use crate::xreg_file::XReg;
    use crate::{isa_test, isa_test_cpu, text, StackSampler};

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

    #[test]
    fn test_jalr_record_call() {
        let text_base = 0u32;
        let text = text![
            jalr(XReg::X1, XReg::X0, 0x0008); // 0x0000, 1) Go to 0x0008, save 0x0004 in X1
            nop();                            // 0x0004
            jalr(XReg::X5, XReg::X0, 0x0010); // 0x0008, 2) Go to 0x0010, save 0x000c in X5
            nop();                            // 0x000c
            jalr(XReg::X1, XReg::X0, 0x0018); // 0x0010, 3) Go to 0x0018, save 0x0014 in X1
            nop();                            // 0x0014
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

    #[test]
    fn test_jalr_record_ret() {
        let text_base = 0u32;
        let text = text![
            jalr(XReg::X1, XReg::X0, 0x0008); // 0x0000, 1) Go to 0x0008, save 0x0004 in X1
            jalr(XReg::X0, XReg::X0, 0x0020); // 0x0004, 6) End
            jalr(XReg::X5, XReg::X0, 0x0010); // 0x0008, 2) Go to 0x0010, save 0x000c in X5
            jalr(XReg::X0, XReg::X1, 0);      // 0x000c, 4) Return to 0x0004
            jalr(XReg::X0, XReg::X5, 0);      // 0x0010, 3) Return to 0x000c
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
        assert_eq!(s.samples.get(&vec![0x0008]), Some(&2));
        assert_eq!(s.samples.get(&vec![0x0008, 0x0010]), Some(&1));
    }

    #[test]
    fn test_jalr_handle_ra_and_link_registers() {
        let text_base = 0u32;
        let text = text![
            jalr(XReg::X1, XReg::X0, 0x000c); // 0x0000, 1) Go to 0x000c, save 0x0004 in X1
            jalr(XReg::X5, XReg::X0, 0x0014); // 0x0004, 3) Go to 0x0014, save 0x0008 in X5
            jalr(XReg::X0, XReg::X1, 0);      // 0x0008, 5) Return to 0x0010
            jalr(XReg::X1, XReg::X1, 0);      // 0x000c, 2) Go to 0x0004, save 0x0010 in X1
            jalr(XReg::X0, XReg::X0, 0xffff); // 0x0010, 6) End
            jalr(XReg::X0, XReg::X5, 0);      // 0x0014, 4) Return to 0x0008
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
        assert_eq!(s.samples.get(&vec![0x000c]), Some(&3));
        assert_eq!(s.samples.get(&vec![0x000c, 0x0004]), Some(&2));
        assert_eq!(s.samples.get(&vec![0x000c, 0x0004, 0x0014]), Some(&1));
    }
}
