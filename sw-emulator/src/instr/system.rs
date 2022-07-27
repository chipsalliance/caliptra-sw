/*++

Licensed under the Apache-2.0 license.

File Name:

    system.rs

Abstract:

    File contains implementation of system instructions.

--*/

use crate::cpu::{Cpu, InstrTracer};
use crate::csr_file::Csr;
use crate::exception::RvException;
use crate::trace_instr;
use crate::types::{
    RvData, RvInstr, RvInstr32I, RvInstr32Opcode, RvInstr32SystemFunct3, RvInstr32SystemImm, RvMStatus,
};

impl Cpu {
    /// Execute system Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_system_instr(
        &mut self,
        instr: u32,
        instr_tracer: Option<InstrTracer>,
    ) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::System);

        // Trace the instruction
        trace_instr!(instr_tracer, self.read_pc(), RvInstr::IType(instr));

        let imm = instr.uimm();

        match instr.funct3().into() {
            RvInstr32SystemFunct3::Priv => match imm.into() {
                RvInstr32SystemImm::Ecall => Err(RvException::environment_call()),
                RvInstr32SystemImm::Ebreak => Err(RvException::breakpoint(self.read_pc())),
                RvInstr32SystemImm::Mret => {
                    let mut status = RvMStatus(self.read_csr(Csr::MSTATUS)?);
                    status.set_mie(status.mpie());
                    status.set_mpie(1);
                    self.write_csr(Csr::MSTATUS, status.0)?;
                    self.write_pc(self.read_csr(Csr::MEPC)?.wrapping_sub(4));
                    Ok(())
                }
                _ => Err(RvException::illegal_instr(instr.0)),
            },
            RvInstr32SystemFunct3::Csrrw => {
                let old_val = self.read_csr(imm)?;
                let new_val = self.read_xreg(instr.rs())?;
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            RvInstr32SystemFunct3::Csrrs => {
                let old_val = self.read_csr(imm)?;
                let new_val = old_val | self.read_xreg(instr.rs())?;
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            RvInstr32SystemFunct3::Csrrc => {
                let old_val = self.read_csr(imm)?;
                let new_val = old_val & !self.read_xreg(instr.rs())?;
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            RvInstr32SystemFunct3::Csrrwi => {
                let old_val = self.read_csr(imm)?;
                let new_val = instr.rs() as RvData;
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            RvInstr32SystemFunct3::Csrrsi => {
                let old_val = self.read_csr(imm)?;
                let new_val = old_val | instr.rs() as RvData;
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            RvInstr32SystemFunct3::Csrrci => {
                let old_val = self.read_csr(imm)?;
                let new_val = old_val & !(instr.rs() as RvData);
                self.write_csr(imm, new_val)?;
                self.write_xreg(instr.rd(), old_val)
            }
            _ => Err(RvException::illegal_instr(instr.0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::csr_file::Csr;
    use crate::exception::RvException;
    use crate::instr::test_encoder::tests::{
        csrrc, csrrci, csrrs, csrrsi, csrrw, csrrwi, ebreak, ecall,
    };
    use crate::xreg_file::XReg;
    use crate::{isa_test, isa_test_cpu, text};

    #[test]
    fn test_ecall() {
        let mut cpu = isa_test_cpu!(0x0000 => text![ecall();], 0x1000 => vec![0]);
        assert_eq!(
            cpu.exec_instr(None).err(),
            Some(RvException::environment_call())
        );
    }

    #[test]
    fn test_ebreak() {
        let mut cpu = isa_test_cpu!(0x0000 => text![ebreak();], 0x1000 => vec![0]);
        assert_eq!(
            cpu.exec_instr(None).err(),
            Some(RvException::breakpoint(0x0000))
        );
    }

    #[test]
    fn test_csrrw() {
        isa_test!(
            0x0000 => text![
                csrrw(XReg::X1, XReg::X2, Csr::MISA);
                csrrw(XReg::X3, XReg::X2, Csr::MEPC);
                csrrw(XReg::X5, XReg::X0, Csr::MEPC);
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = u32::MAX;
            },
            {
                XReg::X1 = 0x4000_1104;
                XReg::X3 = 0x0000_0000;
                XReg::X5 = u32::MAX;
            }
        );
    }

    #[test]
    fn test_unknown_csr() {
        isa_test!(
            0x0000 => text![
                csrrw(XReg::X1, XReg::X2, 4095);
                csrrw(XReg::X3, XReg::X0, 4095);
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = u32::MAX;
            },
            {
                XReg::X1 = 0x0000_0000;
                XReg::X3 = 0x0000_0000;
            }
        );
    }

    #[test]
    fn test_csrrs() {
        isa_test!(
            0x0000 => text![
                csrrs(XReg::X1, XReg::X2, Csr::MSTATUS);
                csrrs(XReg::X3, XReg::X0, Csr::MSTATUS);
                csrrs(XReg::X5, XReg::X0, Csr::MSTATUS);
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = 0x0000_0088;
            },
            {
                XReg::X1 = 0x1800_0000;
                XReg::X3 = 0x1800_0088;
                XReg::X5 = 0x1800_0088;
            }
        );
    }

    #[test]
    fn test_csrrc() {
        isa_test!(
            0x0000 => text![
                csrrs(XReg::X1, XReg::X2, Csr::MSTATUS);
                csrrs(XReg::X3, XReg::X0, Csr::MSTATUS);
                csrrc(XReg::X5, XReg::X2, Csr::MSTATUS);
                csrrs(XReg::X7, XReg::X0, Csr::MSTATUS);
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = 0x0000_0088;
            },
            {
                XReg::X1 = 0x1800_0000;
                XReg::X3 = 0x1800_0088;
                XReg::X5 = 0x1800_0088;
                XReg::X7 = 0x1800_0000;
            }
        );
    }

    #[test]
    fn test_csrrwi() {
        isa_test!(
            0x0000 => text![
                csrrwi(XReg::X1, XReg::X16, Csr::MEPC);
                csrrw(XReg::X3, XReg::X0, Csr::MEPC);
            ],
            0x1000 => vec![0],
            {
            },
            {
                XReg::X1 = 0x0000_0000;
                XReg::X3 = 16;
            }
        );
    }

    #[test]
    fn test_csrrsi() {
        isa_test!(
            0x0000 => text![
                csrrsi(XReg::X1, XReg::X15, Csr::MEPC);
                csrrw(XReg::X3, XReg::X0, Csr::MEPC);
            ],
            0x1000 => vec![0],
            {
            },
            {
                XReg::X1 = 0x0000_0000;
                XReg::X3 = 15;
            }
        );
    }

    #[test]
    fn test_csrrci() {
        isa_test!(
            0x0000 => text![
                csrrsi(XReg::X1, XReg::X15, Csr::MEPC);
                csrrci(XReg::X3, XReg::X1, Csr::MEPC);
                csrrw(XReg::X5, XReg::X0, Csr::MEPC);
            ],
            0x1000 => vec![0],
            {
            },
            {
                XReg::X1 = 0x0000_0000;
                XReg::X3 = 15;
                XReg::X5 = 14;
            }
        );
    }
}
