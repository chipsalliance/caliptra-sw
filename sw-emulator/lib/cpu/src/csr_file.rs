/*++

Licensed under the Apache-2.0 license.

File Name:

    csr_file.rs

Abstract:

    File contains implementation of RISC-v Config and status register file

--*/

use crate::types::{RvMIE, RvMStatus};
use caliptra_emu_bus::{Clock, Timer, TimerAction};
use caliptra_emu_types::{RvAddr, RvData, RvException};

/// Configuration & Status Register
#[derive(Copy, Clone)]
pub struct Csr {
    val: RvData,
    mask: u32,
}

impl Csr {
    /// ISA CSR
    pub const MISA: RvAddr = 0x301;

    /// Vendor ID CSR
    pub const MVENDORID: RvAddr = 0xF11;

    /// Architecture ID CSR
    pub const MARCHID: RvAddr = 0xF12;

    /// Implementation ID CSR
    pub const MIMPIID: RvAddr = 0xF13;

    /// HART ID CSR
    pub const MHARTID: RvAddr = 0xF14;

    /// HART Status CSR
    pub const MSTATUS: RvAddr = 0x300;

    /// Interrupt Enable CSR
    pub const MIE: RvAddr = 0x304;

    /// Interrupt Vector Table Address CSR
    pub const MTVEC: RvAddr = 0x305;

    /// Performance Counter Inhibit register CSR
    pub const MCOUNTINHIBIT: RvAddr = 0x320;

    /// Scratch Register CSR
    pub const MSCRATCH: RvAddr = 0x340;

    /// Exception Program Counter CSR
    pub const MEPC: RvAddr = 0x341;

    /// Exception Cause CSR
    pub const MCAUSE: RvAddr = 0x342;

    /// Exception Value CSR
    pub const MTVAL: RvAddr = 0x343;

    /// Interrupt Pending CSR
    pub const MIP: RvAddr = 0x344;

    /// Cycle Low Counter CSR
    pub const MCYCLE: RvAddr = 0xB00;

    /// Instruction Retired Low Counter CSR
    pub const MINSTRET: RvAddr = 0xB02;

    /// Cycle High Counter CSR
    pub const MCYCLEH: RvAddr = 0xB80;

    /// Instruction Retired High Counter CSR
    pub const MINSTRETH: RvAddr = 0xB82;

    /// External Interrupt Vector Table CSR
    pub const MEIVT: RvAddr = 0xBC8;

    /// External Interrupt Handler Address Pointer CSR
    pub const MEIHAP: RvAddr = 0xFC8;

    /// Create a new Configurations and Status register
    ///
    /// # Arguments
    ///
    /// * `val` - Reset value
    /// * `mask` - Write Mask
    ///'
    pub fn new(val: RvData, mask: RvData) -> Self {
        Self { val, mask }
    }
}

/// Configuration and status register file
pub struct CsrFile {
    /// CSRS
    csrs: [Csr; CsrFile::CSR_COUNT],
    /// Timer
    timer: Timer,
}

impl CsrFile {
    /// Supported CSR Count
    const CSR_COUNT: usize = 4096;

    /// Create a new Configuration and status register file
    pub fn new(clock: &Clock) -> Self {
        let mut csrs = Self {
            csrs: [Csr::new(0, 0); CsrFile::CSR_COUNT],
            timer: Timer::new(clock),
        };

        csrs.reset();
        csrs
    }

    /// Reset the CSR file
    fn reset(&mut self) {
        self.csrs[Csr::MISA as usize] = Csr::new(0x4000_1104, 0);
        self.csrs[Csr::MVENDORID as usize] = Csr::new(0x0000_0045, 0);
        self.csrs[Csr::MARCHID as usize] = Csr::new(0x0000_0010, 0);
        self.csrs[Csr::MIMPIID as usize] = Csr::new(0x0000_0004, 0);
        self.csrs[Csr::MHARTID as usize] = Csr::new(0x0000_0000, 0);
        self.csrs[Csr::MSTATUS as usize] = Csr::new(0x1800_0000, 0x0000_0088);
        self.csrs[Csr::MIE as usize] = Csr::new(0x0000_0000, 0x7000_0888);
        self.csrs[Csr::MTVEC as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MCOUNTINHIBIT as usize] = Csr::new(0x0000_0000, 0x0000_007D);
        self.csrs[Csr::MSCRATCH as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MEPC as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MCAUSE as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MTVAL as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MIP as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MCYCLE as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MCYCLEH as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MINSTRET as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MINSTRETH as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFF);
        self.csrs[Csr::MEIVT as usize] = Csr::new(0x0000_0000, 0xFFFF_FC00);
        self.csrs[Csr::MEIHAP as usize] = Csr::new(0x0000_0000, 0xFFFF_FFFC);
    }

    /// Read the specified configuration status register
    ///
    /// # Arguments
    ///
    /// * `csr` - Configuration status register to read
    ///
    ///  # Return
    ///
    ///  * `RvData` - Register value
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister``
    pub fn read(&self, addr: RvAddr) -> Result<RvData, RvException> {
        let addr = addr as usize;
        const CSR_MAX: usize = CsrFile::CSR_COUNT - 1;
        match addr {
            0..=CSR_MAX => Ok(self.csrs[addr].val),
            _ => Err(RvException::illegal_register()),
        }
    }

    /// Write the specified Configuration status register
    ///
    /// # Arguments
    ///
    /// * `reg` - Configuration  status register to write
    /// * `val` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write(&mut self, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        let addr = addr as usize;
        const CSR_MAX: usize = CsrFile::CSR_COUNT - 1;
        match addr {
            0..=CSR_MAX => {
                let csr = &mut self.csrs[addr];
                csr.val = (csr.val & !csr.mask) | (val & csr.mask);

                if addr == Csr::MEIVT as usize {
                    self.timer
                        .schedule_action_in(0, TimerAction::SetExtIntVec { addr: csr.val });
                }
                if addr == Csr::MSTATUS as usize {
                    let mstatus = RvMStatus(csr.val);
                    self.timer.schedule_action_in(
                        0,
                        TimerAction::SetGlobalIntEn {
                            en: mstatus.mie() == 1,
                        },
                    );
                    // Let's see if the soc wants to interrupt
                    self.timer.schedule_poll_in(2);
                }
                if addr == Csr::MIE as usize {
                    let mie = RvMIE(csr.val);
                    self.timer.schedule_action_in(
                        0,
                        TimerAction::SetExtIntEn {
                            en: mie.meie() == 1,
                        },
                    );
                    // Let's see if the soc wants to interrupt
                    self.timer.schedule_poll_in(2);
                }
                Ok(())
            }
            _ => Err(RvException::illegal_register()),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_read_only_csr() {
        let clock = Clock::new();
        let mut csrs = CsrFile::new(&clock);

        assert_eq!(csrs.read(Csr::MISA).ok(), Some(0x4000_1104));
        assert_eq!(csrs.write(Csr::MISA, u32::MAX).ok(), Some(()));
        assert_eq!(csrs.read(Csr::MISA).ok(), Some(0x4000_1104));
    }

    #[test]
    fn test_read_write_csr() {
        let clock = Clock::new();
        let mut csrs = CsrFile::new(&clock);
        assert_eq!(csrs.read(Csr::MEPC).ok(), Some(0));
        assert_eq!(csrs.write(Csr::MEPC, u32::MAX).ok(), Some(()));
        assert_eq!(csrs.read(Csr::MEPC).ok(), Some(u32::MAX));
    }

    #[test]
    fn test_read_write_masked_csr() {
        let clock = Clock::new();
        let mut csrs = CsrFile::new(&clock);

        assert_eq!(csrs.read(Csr::MSTATUS).ok(), Some(0x1800_0000));
        assert_eq!(csrs.write(Csr::MSTATUS, u32::MAX).ok(), Some(()));
        assert_eq!(csrs.read(Csr::MSTATUS).ok(), Some(0x1800_0088));

        assert_eq!(csrs.read(Csr::MCOUNTINHIBIT).ok(), Some(0x0000_0000));
        assert_eq!(csrs.write(Csr::MCOUNTINHIBIT, u32::MAX).ok(), Some(()));
        assert_eq!(csrs.read(Csr::MCOUNTINHIBIT).ok(), Some(0x0000_007D));
    }
}
