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
    /// * `RvException` - Exception with cause `RvExceptionCause::LoadAccessFault`
    ///                   or `RvExceptionCause::LoadAddrMisaligned`
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError>;

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
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError>;
}
