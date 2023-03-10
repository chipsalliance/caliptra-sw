/*++

Licensed under the Apache-2.0 license.

File Name:

    mem.rs

Abstract:

    File contains implementation of helper data structures to support memory
    devices like ROM, TCM and RAM.

--*/

use crate::BusError;
use caliptra_emu_types::{RvAddr, RvData, RvSize};

/// Memory Exception
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum MemError {
    /// Read Address misaligned
    ReadAddrMisaligned,

    /// Read Access fault
    ReadAccessFault,

    /// Write Address misaligned
    WriteAddrMisaligned,

    /// Write access fault
    WriteAccessFault,
}

impl From<MemError> for BusError {
    /// Converts to this type from the input type.
    fn from(exception: MemError) -> BusError {
        match exception {
            MemError::ReadAddrMisaligned => BusError::LoadAddrMisaligned,
            MemError::ReadAccessFault => BusError::LoadAccessFault,
            MemError::WriteAddrMisaligned => BusError::StoreAddrMisaligned,
            MemError::WriteAccessFault => BusError::StoreAccessFault,
        }
    }
}

/// Memory
#[allow(dead_code)]
pub struct Mem {
    /// Data storage
    data: Vec<u8>,
}

#[allow(dead_code)]
impl Mem {
    /// Create a new memory object
    ///
    /// # Arguments
    ///
    /// * `data` - Data contents for memory
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Size of the memory in bytes
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Immutable reference to data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Mutable reference to data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
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
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    pub fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, MemError> {
        match size {
            RvSize::Byte => self.read_byte(addr as usize),
            RvSize::HalfWord => self.read_half_word(addr as usize),
            RvSize::Word => self.read_word(addr as usize),
            RvSize::Invalid => Err(MemError::ReadAccessFault),
        }
    }

    /// Read data of specified size from given address. This function checks the address
    /// is `size` aligned.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAddrMisaligned` - Read address is not `size` aligned
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    pub fn read_aligned(&self, size: RvSize, addr: RvAddr) -> Result<RvData, MemError> {
        match size {
            RvSize::Byte => self.read_byte(addr as usize),
            RvSize::HalfWord => self.read_aligned_half_word(addr as usize),
            RvSize::Word => self.read_aligned_word(addr as usize),
            RvSize::Invalid => Err(MemError::ReadAccessFault),
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
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    pub fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), MemError> {
        match size {
            RvSize::Byte => self.write_byte(addr as usize, val),
            RvSize::HalfWord => self.write_half_word(addr as usize, val),
            RvSize::Word => self.write_word(addr as usize, val),
            RvSize::Invalid => Err(MemError::WriteAccessFault),
        }
    }

    /// Write data of specified size to given address. This function checks the address
    /// is `size` aligned.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `addr` - Address to write
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemError::WriteAddrMisaligned` - Write address is not `size` aligned
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    pub fn write_aligned(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        data: RvData,
    ) -> Result<(), MemError> {
        match size {
            RvSize::Byte => self.write_byte(addr as usize, data),
            RvSize::HalfWord => self.write_aligned_half_word(addr as usize, data),
            RvSize::Word => self.write_aligned_word(addr as usize, data),
            RvSize::Invalid => Err(MemError::WriteAccessFault),
        }
    }

    /// Read a byte from given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    fn read_byte(&self, addr: usize) -> Result<RvData, MemError> {
        if addr < self.data.len() {
            Ok(self.data[addr] as RvData)
        } else {
            Err(MemError::ReadAccessFault)
        }
    }

    /// Read half word (two bytes) from given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    fn read_half_word(&self, addr: usize) -> Result<RvData, MemError> {
        if addr < self.data.len() && addr + 1 < self.data.len() {
            Ok((self.data[addr] as RvData) | ((self.data[addr + 1] as RvData) << 8))
        } else {
            Err(MemError::ReadAccessFault)
        }
    }

    /// Read word (four bytes) from given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    fn read_word(&self, addr: usize) -> Result<RvData, MemError> {
        if addr < self.data.len() && addr + 3 < self.data.len() {
            Ok((self.data[addr] as RvData)
                | ((self.data[addr + 1] as RvData) << 8)
                | ((self.data[addr + 2] as RvData) << 16)
                | ((self.data[addr + 3] as RvData) << 24))
        } else {
            Err(MemError::ReadAccessFault)
        }
    }

    /// Read aligned half word (two bytes) from given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAddrMisaligned` - Read address is misaligned
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    fn read_aligned_half_word(&self, addr: usize) -> Result<RvData, MemError> {
        if addr < self.data.len() {
            if addr & 1 == 0 {
                self.read_half_word(addr)
            } else {
                Err(MemError::ReadAddrMisaligned)
            }
        } else {
            Err(MemError::ReadAccessFault)
        }
    }

    /// Read aligned word (four bytes) from given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `MemError::ReadAddrMisaligned` - Read address is misaligned
    /// * `MemError::ReadAccessFault` - Read from invalid or non existent address
    #[inline]
    fn read_aligned_word(&self, addr: usize) -> Result<RvData, MemError> {
        if addr < self.data.len() {
            if addr & 3 == 0 {
                self.read_word(addr)
            } else {
                Err(MemError::ReadAddrMisaligned)
            }
        } else {
            Err(MemError::ReadAccessFault)
        }
    }

    /// Write a byte to given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to write to
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    fn write_byte(&mut self, addr: usize, data: RvData) -> Result<(), MemError> {
        if addr < self.data.len() {
            self.data[addr] = data as u8;
            Ok(())
        } else {
            Err(MemError::WriteAccessFault)
        }
    }

    /// Write half word (2 bytes) to given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to write to
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    fn write_half_word(&mut self, addr: usize, data: RvData) -> Result<(), MemError> {
        if addr < self.data.len() && addr + 1 < self.data.len() {
            self.data[addr] = (data & 0xff) as u8;
            self.data[addr + 1] = (data >> 8 & 0xff) as u8;
            Ok(())
        } else {
            Err(MemError::WriteAccessFault)
        }
    }

    /// Write word (4 bytes) to given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to write to
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    fn write_word(&mut self, addr: usize, data: RvData) -> Result<(), MemError> {
        if addr < self.data.len() && addr + 3 < self.data.len() {
            self.data[addr] = (data & 0xff) as u8;
            self.data[addr + 1] = (data >> 8 & 0xff) as u8;
            self.data[addr + 2] = (data >> 16 & 0xff) as u8;
            self.data[addr + 3] = (data >> 24 & 0xff) as u8;
            Ok(())
        } else {
            Err(MemError::WriteAccessFault)
        }
    }

    /// Write aligned half word (2 bytes) to given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to write to
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemException::WriteAddrMisaligned` - Write address is misaligned
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    fn write_aligned_half_word(&mut self, addr: usize, data: RvData) -> Result<(), MemError> {
        if addr < self.data.len() {
            if addr & 1 == 0 {
                self.write_half_word(addr, data)
            } else {
                Err(MemError::WriteAddrMisaligned)
            }
        } else {
            Err(MemError::WriteAccessFault)
        }
    }

    /// Write aligned word (4 bytes) to given address
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to write to
    /// * `data` - Data to write
    ///
    /// # Error
    ///
    /// * `MemException::WriteAddrMisaligned` - Write address is misaligned
    /// * `MemError::WriteAccessFault` - Write to invalid or non existent address
    #[inline]
    fn write_aligned_word(&mut self, addr: usize, data: RvData) -> Result<(), MemError> {
        if addr < self.data.len() {
            if addr & 3 == 0 {
                self.write_word(addr, data)
            } else {
                Err(MemError::WriteAddrMisaligned)
            }
        } else {
            Err(MemError::WriteAccessFault)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! read_test {
        ($func:ident, $size:path, $aligned:literal) => {
            #[test]
            fn $func() {
                fn make_word(size: usize, idx: usize, vec: &[u8]) -> RvData {
                    let mut res: RvData = 0;
                    for i in 0..size {
                        res |= ((vec[idx + i] as RvData) << i * 8);
                    }
                    res
                }

                let size: usize = $size.into();
                let read_fn = if !$aligned {
                    Mem::read
                } else {
                    Mem::read_aligned
                };
                let vec = vec![1, 2, 3, 4, 5];
                let mem = Mem::new(vec.clone());
                let mut i = 0;

                while (mem.len() - i) > (size - 1) {
                    if !$aligned || i & (size - 1) == 0 {
                        assert_eq!(
                            read_fn(&mem, $size, i as RvAddr).ok(),
                            Some(make_word(size, i, &vec))
                        );
                    } else {
                        assert_eq!(
                            read_fn(&mem, $size, i as RvAddr).err(),
                            Some(MemError::ReadAddrMisaligned)
                        );
                    }
                    i += 1;
                }

                while (mem.len() - i) > 1 {
                    if !$aligned || i & (size - 1) == 0 {
                        assert_eq!(
                            read_fn(&mem, $size, i as RvAddr).err(),
                            Some(MemError::ReadAccessFault)
                        );
                    } else {
                        assert_eq!(
                            read_fn(&mem, $size, i as RvAddr).err(),
                            Some(MemError::ReadAddrMisaligned)
                        );
                    }
                    i += 1;
                }

                assert_eq!(
                    read_fn(&mem, $size, i as RvAddr).err(),
                    Some(MemError::ReadAccessFault)
                );
            }
        };
    }

    macro_rules! write_test {
        ($func:ident, $size:path, $aligned:literal) => {
            #[test]
            fn $func() {
                let size: usize = $size.into();
                let write_fn = if !$aligned {
                    Mem::write
                } else {
                    Mem::write_aligned
                };
                let mask = !(u64::MAX.wrapping_shl(8u32 * size as u32)) as u32;
                let vec = vec![0, 0, 0, 0, 0];
                let mut mem = Mem::new(vec.clone());
                let mut i = 0;
                let mut data = 0xCAFEBABE as RvData;

                while mem.len() - i > size - 1 {
                    if !$aligned || i & (size - 1) == 0 {
                        assert_eq!(write_fn(&mut mem, $size, i as RvAddr, data).ok(), Some(()));
                        assert_eq!(mem.read($size, i as RvAddr).ok(), Some(mask & data));
                    } else {
                        assert_eq!(
                            write_fn(&mut mem, $size, i as RvAddr, data).err(),
                            Some(MemError::WriteAddrMisaligned),
                        );
                    }
                    i += 1;
                    data += 1;
                }

                while (mem.len() - i) > 0 {
                    if !$aligned || i & (size - 1) == 0 {
                        assert_eq!(
                            write_fn(&mut mem, $size, i as RvAddr, data).err(),
                            Some(MemError::WriteAccessFault),
                        );
                    } else {
                        assert_eq!(
                            write_fn(&mut mem, $size, i as RvAddr, data).err(),
                            Some(MemError::WriteAddrMisaligned),
                        );
                    }
                    i += 1;
                }

                assert_eq!(
                    write_fn(&mut mem, $size, i as RvAddr, data).err(),
                    Some(MemError::WriteAccessFault),
                );
            }
        };
    }

    #[test]
    fn test_new() {
        // Test zero sized memory
        let mem = Mem::new(Vec::new());
        assert_eq!(mem.len(), 0);

        // Test memory
        let data = vec![1, 2, 3];
        let mem = Mem::new(data.clone());
        assert_eq!(mem.len(), data.len());
    }

    read_test!(test_read_byte, RvSize::Byte, false);
    read_test!(test_read_half_word, RvSize::HalfWord, false);
    read_test!(test_read_word, RvSize::Word, false);

    read_test!(test_read_aligned_byte, RvSize::Byte, true);
    read_test!(test_read_aligned_half_word, RvSize::HalfWord, true);
    read_test!(test_read_aligned_word, RvSize::Word, true);

    write_test!(test_write_byte, RvSize::Byte, false);
    write_test!(test_write_half_word, RvSize::HalfWord, false);
    write_test!(test_write_word, RvSize::Word, false);

    write_test!(test_write_aligned_byte, RvSize::Byte, true);
    write_test!(test_write_aligned_half_word, RvSize::HalfWord, true);
    write_test!(test_write_aligned_word, RvSize::Word, true);
}
