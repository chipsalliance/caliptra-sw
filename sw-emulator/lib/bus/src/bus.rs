/*++

Licensed under the Apache-2.0 license.

File Name:

    bus.rs

Abstract:

    File contains definition of the Bus trait.

--*/

use caliptra_emu_types::{RvAddr, RvData, RvSize};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BusError {
    /// Instruction access exception
    InstrAccessFault,

    /// Load address misaligned exception
    LoadAddrMisaligned,

    /// Load access fault exception
    LoadAccessFault,

    /// Store address misaligned exception
    StoreAddrMisaligned,

    /// Store access fault exception
    StoreAccessFault,
}

/// Represents an abstract memory bus. Used to read and write from RAM and
/// peripheral addresses.
pub trait Bus {
    /// Read data of specified size from given address
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the read
    /// * `addr` - Address to read from
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::LoadAccessFault` or `BusError::LoadAddrMisaligned`
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError>;

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
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError>;

    /// This method is used to notify peripherals of the passage of time. The
    /// owner of this bus MAY call this function periodically, or in response to
    /// a previously scheduled timer event.
    fn poll(&mut self) {
        // By default, do nothing
    }

    fn warm_reset(&mut self) {
        // By default, do nothing
    }

    fn update_reset(&mut self) {
        // By default, do nothing
    }

    fn handle_dma(&mut self) {
        // By default, do nothing
    }
}
