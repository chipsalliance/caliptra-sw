/*++

Licensed under the Apache-2.0 license.

File Name:

    emu_ctrl.rs

Abstract:

    File contains emulation control device implementation.

--*/

use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvException, RvSize};
use std::process::exit;

/// Emulation Control
pub struct EmuCtrl {}

impl EmuCtrl {
    // Exit emulator address
    const ADDR_EXIT: RvAddr = 0x0000_0000;

    /// Create an new instance of emulator control
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the device
    pub fn new() -> Self {
        Self {}
    }
    /// Memory map size.
    pub fn mmap_size(&self) -> RvAddr {
        4
    }
}

impl Bus for EmuCtrl {
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
