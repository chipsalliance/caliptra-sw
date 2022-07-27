/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl.rs

Abstract:

    File contains emulation control device implementation.

--*/

use crate::device::Device;
use crate::exception::RvException;
use crate::types::{RvAddr, RvData, RvIrq, RvSize};
use std::process::exit;

/// Emulation Control
pub struct EmuCtrl {
    /// Device Name
    name: String,

    /// Memory Map address
    mmap_addr: RvAddr,

    /// Memory Map Size
    mmap_size: RvAddr,
}

impl EmuCtrl {
    // Exit emulator address
    const ADDR_EXIT: RvAddr = 0x0000_0000;

    /// Create an new instance of emulator control
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the device
    /// * `addr` - Address of the device
    pub fn new(name: &str, addr: RvAddr) -> Self {
        Self {
            name: String::from(name),
            mmap_addr: addr,
            mmap_size: 4,
        }
    }
}

impl Device for EmuCtrl {
    /// Name of the device
    fn name(&self) -> &str {
        &self.name
    }

    /// Memory mapped address of the device
    fn mmap_addr(&self) -> RvAddr {
        self.mmap_addr
    }

    /// Memory map size.
    fn mmap_size(&self) -> RvAddr {
        self.mmap_size
    }

    /// Memory map range
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
        match (size, addr) {
            (RvSize::Word, EmuCtrl::ADDR_EXIT) => Ok(0),
            _ => Err(RvException::load_access_fault(addr)),
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
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException> {
        match (size, addr) {
            (RvSize::Word, EmuCtrl::ADDR_EXIT) => {
                exit(val as i32);
            }
            _ => Err(RvException::store_access_fault(addr))?,
        }
        Ok(())
    }
}
