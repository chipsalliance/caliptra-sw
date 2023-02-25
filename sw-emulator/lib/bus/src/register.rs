/*++

Licensed under the Apache-2.0 license.

File Name:

    register.rs

Abstract:

    File contains implementation of various register types used by peripherals

--*/

use crate::mem::Mem;
use crate::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::registers::InMemoryRegister;
use tock_registers::{LocalRegisterCopy, RegisterLongName, UIntLike};

pub trait Register {
    /// Size of the register in bytes.
    const SIZE: usize;

    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::LoadAccessFault` or `BusError::LoadAddrMisaligned`
    fn read(&self, size: RvSize) -> Result<RvData, BusError>;

    /// Write data of specified size to given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError>;
}

/// Rv Data Conversion Trait
trait RvDataConverter<T: UIntLike> {
    /// Convert `RvData` to type `T`
    ///
    /// # Arguments
    ///
    /// * `val` - Data to convert
    ///
    /// # Returns
    ///
    /// * `T` - The converted value
    fn from(val: RvData) -> T;

    /// Convert `T` to type `RvData`
    ///
    /// # Arguments
    ///
    /// * `val` - Data to convert
    ///
    /// # Returns
    ///
    /// * `RvData` - The converted value
    fn to(val: T) -> RvData;
}

impl RvDataConverter<u8> for u8 {
    /// Convert `RvData` to type `u8`
    fn from(val: RvData) -> u8 {
        (val & u8::MAX as RvData) as u8
    }

    /// Convert `u8` to type `RvData`
    fn to(val: u8) -> RvData {
        val as RvData
    }
}

impl RvDataConverter<u16> for u16 {
    /// Convert `RvData` to type `u16`
    fn from(val: RvData) -> u16 {
        (val & u16::MAX as RvData) as u16
    }

    /// Convert `u16` to type `RvData`
    fn to(val: u16) -> RvData {
        val as RvData
    }
}

impl RvDataConverter<u32> for u32 {
    /// Convert `RvData` to type `u32`
    fn from(val: RvData) -> u32 {
        val
    }

    /// Convert `u32` to type `RvData`
    fn to(val: u32) -> RvData {
        val
    }
}

impl Register for u8 {
    const SIZE: usize = std::mem::size_of::<Self>();

    /// Read data of specified size from given address
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::Byte => Ok(u8::to(*self)),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Byte => {
                *self = val as u8;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}
impl Register for u16 {
    const SIZE: usize = std::mem::size_of::<Self>();

    /// Read data of specified size from given address
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::HalfWord => Ok(u16::to(*self)),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::HalfWord => {
                *self = val as u16;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}

impl Register for u32 {
    const SIZE: usize = std::mem::size_of::<Self>();

    /// Read data of specified size from given address
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        match size {
            RvSize::Word => Ok(u32::to(*self)),
            _ => Err(BusError::LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        match size {
            RvSize::Word => {
                *self = val;
                Ok(())
            }
            _ => Err(BusError::StoreAccessFault),
        }
    }
}

impl<T: UIntLike + Register, R: RegisterLongName> Register for LocalRegisterCopy<T, R> {
    const SIZE: usize = T::SIZE;

    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        Register::read(&self.get(), size)
    }

    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        let mut tmp = T::zero();
        Register::write(&mut tmp, size, val)?;
        self.set(tmp);
        Ok(())
    }
}

/// Read Write Register
pub struct ReadWriteRegister<T: UIntLike, R: RegisterLongName = ()> {
    /// Register
    pub reg: InMemoryRegister<T, R>,
}

impl<T: UIntLike, R: RegisterLongName> ReadWriteRegister<T, R> {
    /// Create an instance of Read Write Register
    pub fn new(val: T) -> Self {
        Self {
            reg: InMemoryRegister::new(val),
        }
    }
}

impl<T: UIntLike + RvDataConverter<T>, R: RegisterLongName> Register for ReadWriteRegister<T, R> {
    const SIZE: usize = std::mem::size_of::<T>();

    /// Read data of specified size from given address
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        if std::mem::size_of::<T>() != size.into() {
            Err(BusError::LoadAccessFault)?
        }

        Ok(T::to(self.reg.get()))
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if std::mem::size_of::<T>() != size.into() {
            Err(BusError::StoreAccessFault)?
        }

        self.reg.set(T::from(val));

        Ok(())
    }
}

/// Read Only Register
pub struct ReadOnlyRegister<T: UIntLike, R: RegisterLongName = ()> {
    /// Register
    pub reg: InMemoryRegister<T, R>,
}

impl<T: UIntLike, R: RegisterLongName> ReadOnlyRegister<T, R> {
    /// Create an instance of Read Only Register
    pub fn new(val: T) -> Self {
        Self {
            reg: InMemoryRegister::new(val),
        }
    }
}

impl<T: UIntLike + RvDataConverter<T>, R: RegisterLongName> Register for ReadOnlyRegister<T, R>
where
    RvData: From<T>,
{
    const SIZE: usize = std::mem::size_of::<T>();

    /// Read data of specified size from given address
    fn read(&self, size: RvSize) -> Result<RvData, BusError> {
        if std::mem::size_of::<T>() != size.into() {
            Err(BusError::LoadAccessFault)?
        }

        Ok(T::to(self.reg.get()))
    }

    /// Write data of specified size to given address
    fn write(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
}

/// Write Only Register
pub struct WriteOnlyRegister<T: UIntLike, R: RegisterLongName = ()> {
    pub reg: InMemoryRegister<T, R>,
}

impl<T: UIntLike, R: RegisterLongName> WriteOnlyRegister<T, R> {
    /// Create an instance of Write Only Register
    pub fn new(val: T) -> Self {
        Self {
            reg: InMemoryRegister::new(val),
        }
    }
}

impl<T: UIntLike + RvDataConverter<T>, R: RegisterLongName> Register for WriteOnlyRegister<T, R>
where
    RvData: From<T>,
{
    const SIZE: usize = std::mem::size_of::<T>();

    /// Read data of specified size from given address
    fn read(&self, _size: RvSize) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)?
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if std::mem::size_of::<T>() != size.into() {
            Err(BusError::StoreAccessFault)?
        }

        self.reg.set(T::from(val));

        Ok(())
    }
}

/// Fixed sized Read Write Memory
pub struct ReadWriteMemory<const N: usize> {
    data: Mem,
}

impl<const N: usize> ReadWriteMemory<N> {
    /// Create an instance of Read Write Memory
    pub fn new() -> Self {
        Self {
            data: Mem::new(vec![0u8; N]),
        }
    }

    /// Create an instance of Read Only Memory with data
    pub fn new_with_data(data: [u8; N]) -> Self {
        Self {
            data: Mem::new(Vec::from(data)),
        }
    }

    /// Size of the memory in bytes
    pub fn len(&self) -> RvAddr {
        self.data.len() as RvAddr
    }

    /// Immutable reference to data
    pub fn data(&self) -> &[u8; N] {
        let ptr = self.data.data().as_ptr() as *const [u8; N];
        unsafe { &*ptr }
    }

    /// Mutable reference to data
    pub fn data_mut(&mut self) -> &mut [u8; N] {
        let ptr = self.data.data().as_ptr() as *mut [u8; N];
        unsafe { &mut *ptr }
    }
}

impl<const N: usize> Bus for ReadWriteMemory<N> {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match self.data.read(size, addr) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match self.data.write(size, addr, val) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }
}

/// Fixed sized Read Only Memory
pub struct ReadOnlyMemory<const N: usize> {
    data: Mem,
}

impl<const N: usize> ReadOnlyMemory<N> {
    /// Create an instance of Read Only Memory
    pub fn new() -> Self {
        Self {
            data: Mem::new(vec![0u8; N]),
        }
    }

    /// Create an instance of Read Only Memory with data
    pub fn new_with_data(data: [u8; N]) -> Self {
        Self {
            data: Mem::new(Vec::from(data)),
        }
    }

    /// Size of the memory in bytes
    pub fn len(&self) -> RvAddr {
        self.data.len() as RvAddr
    }

    /// Immutable reference to data
    pub fn data(&self) -> &[u8; N] {
        let ptr = self.data.data().as_ptr() as *const [u8; N];
        unsafe { &*ptr }
    }

    /// Mutable reference to data
    pub fn data_mut(&mut self) -> &mut [u8; N] {
        let ptr = self.data.data().as_ptr() as *mut [u8; N];
        unsafe { &mut *ptr }
    }
}

impl<const N: usize> Bus for ReadOnlyMemory<N> {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match self.data.read(size, addr) {
            Ok(data) => Ok(data),
            Err(error) => Err(error.into()),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, _size: RvSize, _addr: RvAddr, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }
}

/// Fixed sized Write Only Memory
pub struct WriteOnlyMemory<const N: usize> {
    data: Mem,
}

impl<const N: usize> WriteOnlyMemory<N> {
    /// Create an instance of Write Only Memory
    pub fn new() -> Self {
        Self {
            data: Mem::new(vec![0u8; N]),
        }
    }
    /// Size of the memory in bytes
    pub fn len(&self) -> RvAddr {
        self.data.len() as RvAddr
    }

    /// Immutable reference to data
    pub fn data(&self) -> &[u8; N] {
        let ptr = self.data.data().as_ptr() as *const [u8; N];
        unsafe { &*ptr }
    }

    /// Mutable reference to data
    pub fn data_mut(&mut self) -> &mut [u8; N] {
        let ptr = self.data.data().as_ptr() as *mut [u8; N];
        unsafe { &mut *ptr }
    }
}

impl<const N: usize> Bus for WriteOnlyMemory<N> {
    /// Read data of specified size from given address
    fn read(&mut self, _size: RvSize, _addr: RvAddr) -> Result<RvData, BusError> {
        Err(BusError::LoadAccessFault)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
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
    fn test_u8_read_write_reg() {
        let mut reg = ReadWriteRegister::<u8>::new(0);

        assert_eq!(reg.read(RvSize::Byte).ok(), Some(0));
        assert_eq!(reg.write(RvSize::Byte, u32::MAX).ok(), Some(()));
        assert_eq!(reg.read(RvSize::Byte).ok(), Some(u8::MAX as RvData));

        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u16_read_write_reg() {
        let mut reg = ReadWriteRegister::<u16>::new(0);

        assert_eq!(reg.read(RvSize::HalfWord).ok(), Some(0));
        assert_eq!(
            reg.write(RvSize::HalfWord, u32::MAX as RvData).ok(),
            Some(())
        );
        assert_eq!(reg.read(RvSize::HalfWord).ok(), Some(u16::MAX as RvData));

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u32_read_write_reg() {
        let mut reg = ReadWriteRegister::<u32>::new(0);

        assert_eq!(reg.read(RvSize::Word).ok(), Some(0));
        assert_eq!(reg.write(RvSize::Word, u32::MAX).ok(), Some(()));
        assert_eq!(reg.read(RvSize::Word).ok(), Some(u32::MAX));

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u8_readonly_reg() {
        let mut reg = ReadOnlyRegister::<u8>::new(u8::MAX);

        assert_eq!(reg.read(RvSize::Byte).ok(), Some(u8::MAX as RvData));

        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u16_readonly_reg() {
        let mut reg = ReadOnlyRegister::<u16>::new(u16::MAX);

        assert_eq!(reg.read(RvSize::HalfWord).ok(), Some(u16::MAX as RvData));

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u32_readonly_reg() {
        let mut reg = ReadOnlyRegister::<u32>::new(u32::MAX);

        assert_eq!(reg.read(RvSize::Word).ok(), Some(u32::MAX));

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u8_writeonly_reg() {
        let mut reg = WriteOnlyRegister::<u8>::new(0);

        assert_eq!(reg.write(RvSize::Byte, u32::MAX).ok(), Some(()));
        assert_eq!(reg.reg.get(), u8::MAX);

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u16_writeonly_reg() {
        let mut reg = WriteOnlyRegister::<u16>::new(0);

        assert_eq!(reg.write(RvSize::HalfWord, u32::MAX).ok(), Some(()));
        assert_eq!(reg.reg.get(), u16::MAX);

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Word, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_u32_writeonly_reg() {
        let mut reg = WriteOnlyRegister::<u32>::new(0);

        assert_eq!(reg.write(RvSize::Word, u32::MAX).ok(), Some(()));
        assert_eq!(reg.reg.get(), u32::MAX);

        assert_eq!(
            reg.read(RvSize::Byte).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::HalfWord).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.read(RvSize::Word).err(),
            Some(BusError::LoadAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::Byte, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
        assert_eq!(
            reg.write(RvSize::HalfWord, 0xFF).err(),
            Some(BusError::StoreAccessFault)
        );
    }

    #[test]
    fn test_read_write_mem() {
        const N: usize = 32;
        let mut mem = ReadWriteMemory::<N>::new();

        for i in 0..N {
            assert_eq!(
                mem.write(RvSize::Byte, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(
                mem.read(RvSize::Byte, i as RvAddr).ok(),
                Some(u8::MAX as RvData)
            );
        }

        for i in (0..N).step_by(2) {
            assert_eq!(
                mem.write(RvSize::HalfWord, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(
                mem.read(RvSize::HalfWord, i as RvAddr).ok(),
                Some(u16::MAX as RvData)
            );
        }

        for i in (0..N).step_by(4) {
            assert_eq!(
                mem.write(RvSize::Word, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(mem.read(RvSize::Word, i as RvAddr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_read_only_mem() {
        const N: usize = 32;
        let mut mem = ReadOnlyMemory::<N>::new_with_data([0xFFu8; N]);

        for i in 0..N {
            assert_eq!(
                mem.write(RvSize::Byte, i as RvAddr, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
            assert_eq!(
                mem.read(RvSize::Byte, i as RvAddr).ok(),
                Some(u8::MAX as RvData)
            );
        }

        for i in (0..N).step_by(2) {
            assert_eq!(
                mem.write(RvSize::HalfWord, i as RvAddr, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
            assert_eq!(
                mem.read(RvSize::HalfWord, i as RvAddr).ok(),
                Some(u16::MAX as RvData)
            );
        }

        for i in (0..N).step_by(4) {
            assert_eq!(
                mem.write(RvSize::Word, i as RvAddr, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
            assert_eq!(mem.read(RvSize::Word, i as RvAddr).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_write_only_mem() {
        const N: usize = 32;
        let mut mem = WriteOnlyMemory::<N>::new();

        for i in 0..N {
            assert_eq!(
                mem.write(RvSize::Byte, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(mem.data()[i], u8::MAX);
            assert_eq!(
                mem.read(RvSize::Byte, i as RvAddr).err(),
                Some(BusError::LoadAccessFault)
            );
        }

        for i in (0..N).step_by(2) {
            assert_eq!(
                mem.write(RvSize::HalfWord, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(mem.data()[i..i + 2], [u8::MAX; 2]);
            assert_eq!(
                mem.read(RvSize::Byte, i as RvAddr).err(),
                Some(BusError::LoadAccessFault)
            )
        }

        for i in (0..N).step_by(4) {
            assert_eq!(
                mem.write(RvSize::Word, i as RvAddr, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(mem.data()[i..i + 4], [u8::MAX; 4]);
            assert_eq!(
                mem.read(RvSize::Byte, i as RvAddr).err(),
                Some(BusError::LoadAccessFault)
            )
        }
    }
}
