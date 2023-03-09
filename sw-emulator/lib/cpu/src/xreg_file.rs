/*++

Licensed under the Apache-2.0 license.

File Name:

    xreg_file.rs

Abstract:

    File contains implementation of RISC-v general purpose register file

--*/

use caliptra_emu_types::{emu_enum, RvAddr, RvData, RvException};

emu_enum!(
    /// RISCV general purpose registers
    #[derive(PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
    pub XReg;
    RvAddr;
    {
        X0 = 0,
        X1 = 1,
        X2 = 2,
        X3 = 3,
        X4 = 4,
        X5 = 5,
        X6 = 6,
        X7 = 7,
        X8 = 8,
        X9 = 9,
        X10 = 10,
        X11 = 11,
        X12 = 12,
        X13 = 13,
        X14 = 14,
        X15 = 15,
        X16 = 16,
        X17 = 17,
        X18 = 18,
        X19 = 19,
        X20 = 20,
        X21 = 21,
        X22 = 22,
        X23 = 23,
        X24 = 24,
        X25 = 25,
        X26 = 26,
        X27 = 27,
        X28 = 28,
        X29 = 29,
        X30 = 30,
        X31 = 31,
    };
    Invalid
);
impl From<u16> for XReg {
    fn from(val: u16) -> Self {
        XReg::from(u32::from(val))
    }
}
impl From<XReg> for u16 {
    fn from(val: XReg) -> Self {
        u16::try_from(u32::from(val)).unwrap()
    }
}

/// RISCV General purpose register file
pub struct XRegFile {
    /// Registers
    reg: [RvData; XRegFile::REG_COUNT],
}

impl XRegFile {
    /// Register count
    const REG_COUNT: usize = 32;

    /// Reset Value
    const RESET_VAL: RvData = 0;

    /// Create an instance of RISCV General purpose register file
    pub fn new() -> Self {
        Self {
            reg: [XRegFile::RESET_VAL; XRegFile::REG_COUNT],
        }
    }

    /// Reset all the registers to default value
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.reg = [XRegFile::RESET_VAL; XRegFile::REG_COUNT]
    }

    /// Reads the specified register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to read
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read(&self, reg: XReg) -> Result<RvData, RvException> {
        match reg {
            XReg::X0 => Ok(0),
            r if (XReg::X1..=XReg::X31).contains(&r) => {
                let reg: RvAddr = reg.into();
                Ok(self.reg[reg as usize])
            }
            _ => Err(RvException::illegal_register()),
        }
    }

    /// Writes the value to specified register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to write
    /// * `value` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write(&mut self, reg: XReg, val: RvData) -> Result<(), RvException> {
        match reg {
            XReg::X0 => Ok(()),
            r if (XReg::X1..=XReg::X31).contains(&r) => {
                let reg: RvAddr = reg.into();
                self.reg[reg as usize] = val;
                Ok(())
            }
            _ => Err(RvException::illegal_register()),
        }
    }
}
impl Default for XRegFile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let reg_file = XRegFile::new();
        for reg in 0..31u32 {
            assert_eq!(reg_file.read(reg.into()).ok(), Some(0))
        }
    }

    #[test]
    fn test_reset() {
        let mut reg_file = XRegFile::new();
        for reg in 1..31u32 {
            assert_eq!(reg_file.write(reg.into(), RvData::MAX).ok(), Some(()));
            assert_eq!(reg_file.read(reg.into()).ok(), Some(RvData::MAX))
        }

        reg_file.reset();

        for reg in 0..31u32 {
            assert_eq!(reg_file.read(reg.into()).ok(), Some(0))
        }
    }

    #[test]
    fn test_x0() {
        let mut reg_file = XRegFile::new();
        assert_eq!(reg_file.write(XReg::X0, RvData::MAX).ok(), Some(()));
        assert_eq!(reg_file.read(XReg::X0).ok(), Some(0));
    }

    #[test]
    fn test_read_write() {
        let mut reg_file = XRegFile::new();

        for reg in 1..31u32 {
            assert_eq!(reg_file.write(reg.into(), RvData::MAX).ok(), Some(()));
            assert_eq!(reg_file.read(reg.into()).ok(), Some(RvData::MAX))
        }
    }

    #[test]
    fn test_read_invalid_reg() {
        let reg_file = XRegFile::new();
        assert_eq!(
            reg_file.read(XReg::Invalid).err(),
            Some(RvException::illegal_register())
        )
    }

    #[test]
    fn test_write_invalid_reg() {
        let mut reg_file = XRegFile::new();
        assert_eq!(
            reg_file.write(XReg::Invalid, RvData::MAX).err(),
            Some(RvException::illegal_register())
        )
    }
}
