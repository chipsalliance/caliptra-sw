/*++

Licensed under the Apache-2.0 license.

File Name:

    iccm.rs

Abstract:

    File contains ICCM Implementation

--*/
use caliptra_emu_bus::Bus;
use caliptra_emu_bus::BusError;
use caliptra_emu_bus::BusError::StoreAccessFault;
use caliptra_emu_bus::Ram;
use caliptra_emu_types::RvAddr;
use caliptra_emu_types::RvData;
use caliptra_emu_types::RvSize;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone)]
pub struct Iccm {
    iccm: Rc<RefCell<IccmImpl>>,
}
const ICCM_SIZE_BYTES: usize = 128 * 1024;

impl Iccm {
    pub fn lock(&mut self) {
        self.iccm.borrow_mut().locked = true;
    }

    pub fn unlock(&mut self) {
        self.iccm.borrow_mut().locked = false;
    }

    pub fn new() -> Self {
        Self {
            iccm: Rc::new(RefCell::new(IccmImpl::new())),
        }
    }
}

impl Default for Iccm {
    fn default() -> Self {
        Iccm::new()
    }
}

struct IccmImpl {
    ram: Ram,
    locked: bool,
}

impl IccmImpl {
    pub fn new() -> Self {
        Self {
            ram: Ram::new(vec![0; ICCM_SIZE_BYTES]),
            locked: false,
        }
    }
}

impl Bus for Iccm {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.iccm.borrow_mut().ram.read(size, addr)
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if self.iccm.borrow_mut().locked {
            return Err(StoreAccessFault);
        }

        self.iccm.borrow_mut().ram.write(size, addr, val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlocked_write() {
        let mut iccm = Iccm::new();
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert_eq!(
                iccm.write(RvSize::Word, word_offset, u32::MAX).ok(),
                Some(())
            );
            assert_eq!(iccm.read(RvSize::Word, word_offset).ok(), Some(u32::MAX));
        }
    }

    #[test]
    fn test_locked_write() {
        let mut iccm = Iccm::new();
        iccm.lock();
        for word_offset in (0u32..ICCM_SIZE_BYTES as u32).step_by(4) {
            assert_eq!(iccm.read(RvSize::Word, word_offset).unwrap(), 0);
            assert_eq!(
                iccm.write(RvSize::Word, word_offset, u32::MAX).err(),
                Some(BusError::StoreAccessFault)
            );
        }
    }
}
