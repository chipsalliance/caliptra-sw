/*++

Licensed under the Apache-2.0 license.

File Name:

    rom.rs

Abstract:

    File contains implementation of ROM

--*/

use crate::mem::Mem;
use crate::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvException, RvSize};

/// Read Only Memory Device
pub struct Rom {
    /// Read Only Data
    data: Mem,
}

impl Rom {
    /// Create new ROM
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the device
    /// * `addr` - Address of the ROM in the address map
    /// * `data` - Data to be stored in the ROM
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Mem::new(data),
        }
    }

    pub fn mmap_size(&self) -> RvAddr {
        self.data.len() as RvAddr
    }
}

impl Bus for Rom {
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
    fn write(&mut self, _size: RvSize, addr: RvAddr, _value: RvData) -> Result<(), RvException> {
        Err(RvException::store_access_fault(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let _rom = Rom::new(vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_mmap_size() {
        let rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(rom.mmap_size(), 4)
    }

    #[test]
    fn test_read() {
        let rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(rom.read(RvSize::Byte, 0).ok(), Some(1));
        assert_eq!(rom.read(RvSize::HalfWord, 0).ok(), Some(1 | 2 << 8));
        assert_eq!(
            rom.read(RvSize::Word, 0).ok(),
            Some(1 | 2 << 8 | 3 << 16 | 4 << 24)
        );
    }

    #[test]
    fn test_read_error() {
        let rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(
            rom.read(RvSize::Byte, rom.mmap_size()).err(),
            Some(RvException::load_access_fault(rom.mmap_size() as u32))
        )
    }

    #[test]
    fn test_write() {
        let mut rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(
            rom.write(RvSize::Byte, 0, u32::MAX).err(),
            Some(RvException::store_access_fault(0))
        )
    }
}
