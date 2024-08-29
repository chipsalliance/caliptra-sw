/*++

Licensed under the Apache-2.0 license.

File Name:

    system.rs

Abstract:

    File contains implementation of system instructions.

--*/

use crate::cpu::Cpu;
use crate::csr_file::Csr;
use crate::types::{
    RvInstr32I, RvInstr32Opcode, RvInstr32SystemFunct3, RvInstr32SystemImm, RvMStatus, RvPrivMode,
};
use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvData, RvException};

impl<TBus: Bus> Cpu<TBus> {
    /// Execute system Instructions
    ///
    /// # Arguments
    ///
    /// * `instr_tracer` - Instruction tracer
    ///
    /// # Error
    ///
    /// * `RvException` - Exception encountered during instruction execution
    pub fn exec_system_instr(&mut self, instr: u32) -> Result<(), RvException> {
        // Decode the instruction
        let instr = RvInstr32I(instr);
        assert_eq!(instr.opcode(), RvInstr32Opcode::System);

        let imm = instr.uimm();

        match instr.funct3().into() {
            RvInstr32SystemFunct3::Priv => match imm.into() {
                RvInstr32SystemImm::Wfi => {
                    // TODO: If S-mode is present, we need to check TW=1 and return an illegal instruction exception
                    // if this is called from U mode.
                    // According to the spec, we can simply treat WFI as NOP since we are allowed to return
                    // from WFI for any reason, and we don't have any power optimization in the emulator.
                    Ok(())
                }
                RvInstr32SystemImm::Ecall => Err(match self.priv_mode {
                    RvPrivMode::M => RvException::environment_call_machine(),
                    RvPrivMode::U => RvException::environment_call_user(),
                    _ => unreachable!(),
                }),
                RvInstr32SystemImm::Ebreak => Err(RvException::breakpoint(self.read_pc())),
                RvInstr32SystemImm::Mret => {
                    if self.priv_mode == RvPrivMode::U {
                        return Err(RvException::illegal_instr(instr.0));
                    }

                    let mut status = RvMStatus(self.read_csr(Csr::MSTATUS)?);
                    status.set_mie(status.mpie());
                    status.set_mpie(1);
                    #[cfg(not(feature = "1.x"))]
                    {
                        let mpp = status.mpp();
                        status.set_mpp(RvPrivMode::U);
                        self.priv_mode = mpp;
                    }
                    self.write_csr(Csr::MSTATUS, status.0)?;
                    self.set_next_pc(self.read_csr(Csr::MEPC)?);
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
    use crate::instr::test_encoder::tests::{
        csrrc, csrrci, csrrs, csrrsi, csrrw, csrrwi, ebreak, ecall,
    };
    use crate::xreg_file::XReg;
    use crate::{isa_test, isa_test_cpu, text};
    use caliptra_emu_types::RvException;

    #[test]
    fn test_ecall() {
        let mut cpu = isa_test_cpu!(0x0000 => text![ecall();], 0x1000 => vec![0]);
        assert_eq!(
            cpu.exec_instr(None).err(),
            Some(RvException::environment_call_machine())
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
        #[cfg(feature = "1.x")]
        const KNOWN_ISA: u32 = 0x4000_1104;
        #[cfg(not(feature = "1.x"))]
        const KNOWN_ISA: u32 = 0x4010_1104;
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
                XReg::X1 = KNOWN_ISA;
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
    #[cfg(feature = "1.x")]
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
    #[cfg(not(feature = "1.x"))]
    fn test_csrrs() {
        isa_test!(
            0x0000 => text![
                csrrs(XReg::X1, XReg::X2, Csr::MSTATUS);
                csrrs(XReg::X3, XReg::X0, Csr::MSTATUS);
                csrrs(XReg::X5, XReg::X0, Csr::MSTATUS);
            ],
            0x1000 => vec![0],
            {
                XReg::X2 = 0x0000_1888;
            },
            {
                XReg::X1 = 0x1800_1800;
                XReg::X3 = 0x1800_1888;
                XReg::X5 = 0x1800_1888;
            }
        );
    }

    #[test]
    #[cfg(feature = "1.x")]
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
    #[cfg(not(feature = "1.x"))]
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
                XReg::X2 = 0x0000_1888;
            },
            {
                XReg::X1 = 0x1800_1800;
                XReg::X3 = 0x1800_1888;
                XReg::X5 = 0x1800_1888;
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
