/*++

Licensed under the Apache-2.0 license.

File Name:

    ram.rs

Abstract:

    File contains implementation of RAM

--*/

use crate::device::Device;
use crate::exception::RvException;
use crate::mem::Mem;
use crate::types::{RvAddr, RvData, RvIrq, RvSize};

/// Read Only Memory Device
pub struct Ram {
    /// Name of the device
    name: String,

    /// Memory map address
    addr: RvAddr,

    /// Read Only Data
    data: Mem,
}

impl Ram {
    /// Create new RAM
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the device
    /// * `addr` - Address of the RAM in the address map
    /// * `data` - Data to be stored in the RAM
    pub fn new(name: &str, addr: RvAddr, data: Vec<u8>) -> Self {
        Self {
            name: String::from(name),
            addr,
            data: Mem::new(data),
        }
    }
}

impl Device for Ram {
    /// Name of the device
    fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Memory mapped address of the device
    fn mmap_addr(&self) -> RvAddr {
        self.addr
    }

    /// Memory map size
    fn mmap_size(&self) -> RvAddr {
        self.data.len() as RvAddr
    }

    /// Return the pending IRQ
    fn pending_irq(&self) -> Option<RvIrq> {
        None
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
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException> {
        match self.data.read(size, addr) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///                   or `RvExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        match self.data.write(size, addr, val) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let _ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_name() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.name(), "RAM")
    }

    #[test]
    fn test_mmap_addr() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.mmap_addr(), 0)
    }

    #[test]
    fn test_mmap_size() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.mmap_size(), 4)
    }

    #[test]
    fn test_pending_irq() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.pending_irq(), None)
    }

    #[test]
    fn test_read() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.read(RvSize::Byte, 0).ok(), Some(1));
        assert_eq!(ram.read(RvSize::HalfWord, 0).ok(), Some(1 | 2 << 8));
        assert_eq!(
            ram.read(RvSize::Word, 0).ok(),
            Some(1 | 2 << 8 | 3 << 16 | 4 << 24)
        );
    }

    #[test]
    fn test_read_error() {
        let ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(
            ram.read(RvSize::Byte, ram.mmap_size()).err(),
            Some(RvException::load_access_fault(ram.mmap_size() as u32))
        )
    }

    #[test]
    fn test_write() {
        let mut ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(ram.write(RvSize::Byte, 0, u32::MAX).ok(), Some(()))
    }

    #[test]
    fn test_write_error() {
        let mut ram = Ram::new("RAM", 0, vec![1, 2, 3, 4]);
        assert_eq!(
            ram.write(RvSize::Byte, ram.mmap_size(), 0).err(),
            Some(RvException::store_access_fault(ram.mmap_size() as u32))
        )
    }
}
