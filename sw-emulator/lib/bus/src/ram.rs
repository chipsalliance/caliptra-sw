/*++

Licensed under the Apache-2.0 license.

File Name:

    ram.rs

Abstract:

    File contains implementation of RAM

--*/

use crate::{mem::Mem, Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

/// Trait defining memory access behavior
pub trait MemAccess {
    fn read_mem(mem: &Mem, size: RvSize, addr: RvAddr) -> Result<RvData, crate::mem::MemError>;
    fn write_mem(
        mem: &mut Mem,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), crate::mem::MemError>;
}

/// Unaligned memory access (current behavior)
pub struct UnalignedAccess;

impl MemAccess for UnalignedAccess {
    fn read_mem(mem: &Mem, size: RvSize, addr: RvAddr) -> Result<RvData, crate::mem::MemError> {
        mem.read(size, addr)
    }

    fn write_mem(
        mem: &mut Mem,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), crate::mem::MemError> {
        mem.write(size, addr, val)
    }
}

/// Aligned memory access
pub struct AlignedAccess;

impl MemAccess for AlignedAccess {
    fn read_mem(mem: &Mem, size: RvSize, addr: RvAddr) -> Result<RvData, crate::mem::MemError> {
        mem.read_aligned(size, addr)
    }

    fn write_mem(
        mem: &mut Mem,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), crate::mem::MemError> {
        mem.write_aligned(size, addr, val)
    }
}

/// Random Access Memory Device
pub struct RamImpl<T: MemAccess = UnalignedAccess> {
    /// Inject double-bit ECC errors on read
    pub error_injection: u8,
    /// Random Access Data
    data: Mem,
    /// Memory access behavior
    _phantom: std::marker::PhantomData<T>,
}

impl<T: MemAccess> RamImpl<T> {
    /// Create new RAM
    ///
    /// # Arguments
    ///
    /// * `data` - Data to be stored in the RAM
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            error_injection: 0,
            data: Mem::new(data),
            _phantom: std::marker::PhantomData,
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

impl<T: MemAccess> Bus for RamImpl<T> {
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
    ///                   or `BusExceptionCause::LoadAddrMisaligned`
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if 2 == self.error_injection {
            return Err(BusError::InstrAccessFault);
        }
        if 8 == self.error_injection {
            return Err(BusError::LoadAccessFault);
        }
        match T::read_mem(&self.data, size, addr) {
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
    ///                   or `BusExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match T::write_mem(&mut self.data, size, addr, val) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }
}

/// Type alias for unaligned RAM (default behavior)
pub type Ram = RamImpl<UnalignedAccess>;

/// Type alias for aligned RAM
pub type AlignedRam = RamImpl<AlignedAccess>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BusError;

    #[test]
    fn test_new() {
        let _ram = Ram::new(vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_read() {
        let mut ram = Ram::new(vec![1, 2, 3, 4]);
        assert_eq!(ram.read(RvSize::Byte, 0).ok(), Some(1));
        assert_eq!(ram.read(RvSize::HalfWord, 0).ok(), Some(1 | (2 << 8)));
        assert_eq!(
            ram.read(RvSize::Word, 0).ok(),
            Some(1 | (2 << 8) | (3 << 16) | (4 << 24))
        );
    }

    #[test]
    fn test_read_error() {
        let mut ram = Ram::new(vec![1, 2, 3, 4]);
        assert_eq!(
            ram.read(RvSize::Byte, ram.len()).err(),
            Some(BusError::LoadAccessFault),
        )
    }

    #[test]
    fn test_write() {
        let mut ram = Ram::new(vec![1, 2, 3, 4]);
        assert_eq!(ram.write(RvSize::Byte, 0, u32::MAX).ok(), Some(()))
    }

    #[test]
    fn test_write_error() {
        let mut ram = Ram::new(vec![1, 2, 3, 4]);
        assert_eq!(
            ram.write(RvSize::Byte, ram.len(), 0).err(),
            Some(BusError::StoreAccessFault),
        )
    }
}
