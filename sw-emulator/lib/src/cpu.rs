/*++

Licensed under the Apache-2.0 license.

File Name:

    cpu.rs

Abstract:

    File contains the implementation of Caliptra CPU.

--*/

use crate::csr_file::{Csr, CsrFile};
use crate::device::Device;
use crate::exception::{RvException, RvExceptionCause};
use crate::types::{RvAddr, RvData, RvInstr, RvMStatus, RvSize};
use crate::xreg_file::{XReg, XRegFile};

pub type InstrTracer = fn(pc: u32, instr: RvInstr);

/// RISCV CPU
pub struct Cpu {
    /// General Purpose register file
    xregs: XRegFile,

    /// Configuration & status registers
    csrs: CsrFile,

    // Program counter
    pc: RvData,

    /// The next program counter after the current instruction is finished executing.
    next_pc: RvData,

    /// Devices connected to the CPU
    devs: Vec<Box<dyn Device>>,
}

/// Cpu instruction step action
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StepAction {
    /// Continue
    Continue,

    /// Fatal
    Fatal,
}

impl Cpu {
    /// Default Program counter reset value
    const PC_RESET_VAL: RvData = 0;

    /// Create a new RISCV CPU
    pub fn new() -> Self {
        Self {
            xregs: XRegFile::new(),
            csrs: CsrFile::new(),
            pc: Cpu::PC_RESET_VAL,
            next_pc: Cpu::PC_RESET_VAL,
            devs: Vec::new(),
        }
    }

    /// Read the RISCV CPU Program counter
    ///
    ///  # Return
    ///
    ///  * `RvData` - PC value.
    pub fn read_pc(&self) -> RvData {
        self.pc
    }

    /// Write the RISCV CPU Program counter
    ///
    /// # Arguments
    ///
    /// * `pc` - Program counter value
    pub fn write_pc(&mut self, pc: RvData) {
        self.pc = pc;
    }

    /// Returns the next program counter after the current instruction is finished executing.
    pub fn next_pc(&self) -> RvData {
        self.next_pc
    }

    /// Set the next program counter after the current instruction is finished executing.
    ///
    /// Should only be set by instruction implementations.
    pub fn set_next_pc(&mut self, next_pc: RvData) {
        self.next_pc = next_pc;
    }

    /// Read the specified RISCV General Purpose Register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to read
    ///
    ///  # Return
    ///
    ///  * `RvData` - Register value if addr is valid; u32::MAX otherwise.
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read_xreg(&self, reg: XReg) -> Result<RvData, RvException> {
        self.xregs.read(reg)
    }

    /// Write the specified RISCV General Purpose Register
    ///
    /// # Arguments
    ///
    /// * `reg` - Register to write
    /// * `val` - Value to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn write_xreg(&mut self, reg: XReg, val: RvData) -> Result<(), RvException> {
        self.xregs.write(reg, val)
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
    /// * `RvException` - Exception with cause `RvExceptionCause::IllegalRegister`
    pub fn read_csr(&self, csr: RvAddr) -> Result<RvData, RvException> {
        self.csrs.read(csr)
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
    pub fn write_csr(&mut self, csr: RvAddr, val: RvData) -> Result<(), RvException> {
        self.csrs.write(csr, val)
    }

    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    pub fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        let dev = self.devs.iter().find(|d| d.mmap_range().contains(&addr));
        match dev {
            Some(dev) => dev.read(size, addr - dev.mmap_addr()),
            None => Err(RvException::load_access_fault(addr)),
        }
    }
    /// Read instruction
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    pub fn read_instr(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        match size {
            RvSize::Byte => Err(RvException::instr_access_fault(addr)),
            _ => match self.read(size, addr) {
                Ok(val) => Ok(val),
                Err(exception) => match exception.cause() {
                    RvExceptionCause::LoadAccessFault => {
                        Err(RvException::instr_access_fault(exception.info()))
                    }
                    RvExceptionCause::LoadAddrMisaligned => {
                        Err(RvException::instr_addr_misaligned(exception.info()))
                    }
                    _ => Err(exception),
                },
            },
        }
    }

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///                   or `RvExceptionCause::StoreAddrMisaligned`
    pub fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        let dev = self
            .devs
            .iter_mut()
            .find(|d| d.mmap_range().contains(&addr));
        match dev {
            Some(dev) => dev.write(size, addr - dev.mmap_addr(), val),
            None => Err(RvException::store_access_fault(addr)),
        }
    }

    /// Attach the specified device to the CPU
    ///
    /// # Arguments
    ///
    /// * `dev` - Device to attach
    pub fn attach_dev(&mut self, dev: Box<dyn Device>) -> bool {
        let mut index = 0;
        let dev_addr = dev.mmap_range();
        for cur_dev in self.devs.iter() {
            let cur_dev_addr = cur_dev.mmap_range();
            // Check if the device range overlaps existing device
            if dev_addr.end() >= cur_dev_addr.start() && dev_addr.start() <= cur_dev_addr.end() {
                return false;
            }
            // Found the position to insert the device
            if dev_addr.start() < cur_dev_addr.start() {
                break;
            }
            index += 1;
        }
        self.devs.insert(index, dev);
        true
    }

    /// Return the list of devices attached to the CPU
    ///
    ///  # Return
    ///
    ///  * `&Vec<Box<dyn Device>>` - List of devices
    #[allow(dead_code)]
    pub fn devs(&self) -> &Vec<Box<dyn Device>> {
        &self.devs
    }

    /// Step a single instruction
    ///
    /// # Error
    ///
    /// * `RvException` - Exception
    pub fn step(&mut self, instr_tracer: Option<InstrTracer>) -> StepAction {
        match self.exec_instr(instr_tracer) {
            Ok(_) => StepAction::Continue,
            Err(exception) => self.handle_exception(exception),
        }
    }

    /// Handle synchronous exception
    ///
    /// # Error
    ///
    /// * `RvException` - Exception
    fn handle_exception(&mut self, exception: RvException) -> StepAction {
        let ret = self.handle_trap(
            false,
            self.read_pc(),
            exception.cause().into(),
            exception.info(),
        );
        match ret {
            Ok(_) => StepAction::Continue,
            Err(_) => StepAction::Fatal,
        }
    }

    /// Handle synchronous & asynchronous trap
    ///
    /// # Error
    ///
    /// * `RvException` - Exception
    fn handle_trap(
        &mut self,
        _intr: bool,
        pc: RvAddr,
        cause: u32,
        info: u32,
    ) -> Result<(), RvException> {
        // TODO: Implement Interrupt Handling
        // 1. Support for vectored asynchronous interrupts
        // 2. Veer fast external interrupt support
        assert!(!_intr);

        self.write_csr(Csr::MEPC, pc)?;
        self.write_csr(Csr::MCAUSE, cause)?;
        self.write_csr(Csr::MTVAL, info)?;

        let mut status = RvMStatus(self.read_csr(Csr::MSTATUS)?);
        status.set_mpie(status.mie());
        status.set_mie(0);
        self.write_csr(Csr::MSTATUS, status.0)?;

        let next_pc = self.read_csr(Csr::MTVEC)? & !0x11;
        self.write_pc(next_pc);
        println!("{:x}", next_pc);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ram::Ram;
    use crate::rom::Rom;

    #[test]
    fn test_new() {
        let cpu = Cpu::new();
        assert_eq!(cpu.read_pc(), 0);
    }

    #[test]
    fn test_pc() {
        let mut cpu = Cpu::new();
        cpu.write_pc(0xFF);
        assert_eq!(cpu.read_pc(), 0xFF);
    }

    #[test]
    fn test_xreg() {
        let mut cpu = Cpu::new();
        for reg in 1..32u32 {
            assert_eq!(cpu.write_xreg(reg.into(), 0xFF).ok(), Some(()));
            assert_eq!(cpu.read_xreg(reg.into()).ok(), Some(0xFF));
        }
    }

    #[test]
    fn test_read() {
        let mut cpu = Cpu::new();
        let rom = Rom::new("ROM0", 1, vec![1, 2]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), true);
        assert_eq!(cpu.read(RvSize::Byte, 1).ok(), Some(1));
        assert_eq!(cpu.read(RvSize::Byte, 2).ok(), Some(2));
        assert_eq!(
            cpu.read(RvSize::Byte, 3).err(),
            Some(RvException::load_access_fault(3))
        );
    }

    #[test]
    fn test_write() {
        let mut cpu = Cpu::new();
        let rom = Ram::new("RAM0", 1, vec![1, 2]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), true);
        assert_eq!(cpu.write(RvSize::Byte, 1, 3).ok(), Some(()));
        assert_eq!(cpu.read(RvSize::Byte, 1).ok(), Some(3));
        assert_eq!(cpu.write(RvSize::Byte, 2, 4).ok(), Some(()));
        assert_eq!(cpu.read(RvSize::Byte, 2).ok(), Some(4));
        assert_eq!(
            cpu.write(RvSize::Byte, 3, 0).err(),
            Some(RvException::store_access_fault(3))
        );
    }

    fn is_sorted<T>(slice: &[T]) -> bool
    where
        T: Ord,
    {
        slice.windows(2).all(|s| s[0] <= s[1])
    }

    #[test]
    fn test_attach_dev() {
        let mut cpu = Cpu::new();
        let rom = Rom::new("ROM0", 1, vec![1, 2]);
        // Attach valid devices
        assert_eq!(cpu.attach_dev(Box::new(rom)), true);
        let rom = Rom::new("ROM1", 0, vec![1]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), true);
        let rom = Rom::new("ROM2", 3, vec![1]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), true);
        // Try inserting devices whose address maps overlap existing devices
        let rom = Rom::new("ROM1", 1, vec![1]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), false);
        let rom = Rom::new("ROM1", 2, vec![1]);
        assert_eq!(cpu.attach_dev(Box::new(rom)), false);
        let addrs: Vec<RvAddr> = cpu
            .devs()
            .iter()
            .flat_map(|d| [d.mmap_addr(), d.mmap_addr() + d.mmap_size() - 1])
            .collect();
        assert_eq!(addrs.len(), 6);
        assert!(is_sorted(&addrs));
    }
}
