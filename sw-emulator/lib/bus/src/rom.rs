/*++

Licensed under the Apache-2.0 license.

File Name:

    rom.rs

Abstract:

    File contains implementation of ROM

--*/

use crate::mem::Mem;
use crate::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

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

    /// Size of the memory in bytes
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> RvAddr {
        self.data.len() as RvAddr
    }

    /// Immutable reference to data
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    /// Mutable reference to data
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.data_mut()
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
    /// * `BusException` - Exception with cause `BusExceptionCause::LoadAccessFault`
    ///   or `BusExceptionCause::LoadAddrMisaligned`
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
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
    /// * `BusException` - Exception with cause `BusExceptionCause::StoreAccessFault`
    ///   or `BusExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, _size: RvSize, _addr: RvAddr, _value: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
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
        assert_eq!(rom.len(), 4)
    }

    #[test]
    fn test_read() {
        let mut rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(rom.read(RvSize::Byte, 0).ok(), Some(1));
        assert_eq!(rom.read(RvSize::HalfWord, 0).ok(), Some(1 | 2 << 8));
        assert_eq!(
            rom.read(RvSize::Word, 0).ok(),
            Some(1 | 2 << 8 | 3 << 16 | 4 << 24)
        );
    }

    #[test]
    fn test_read_error() {
        let mut rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(
            rom.read(RvSize::Byte, rom.len()).err(),
            Some(BusError::LoadAccessFault),
        )
    }

    #[test]
    fn test_write() {
        let mut rom = Rom::new(vec![1, 2, 3, 4]);
        assert_eq!(
            rom.write(RvSize::Byte, 0, u32::MAX).err(),
            Some(BusError::StoreAccessFault),
        )
    }
}
