/*++

Licensed under the Apache-2.0 license.

File Name:

    device.rs

Abstract:

    File contains definition of the Device trait.

--*/

use caliptra_emu_types::{RvAddr, RvData, RvException, RvIrq, RvSize};
use std::ops::RangeInclusive;

/// Device Trait
pub trait Device {
    /// Name of the device
    fn name(&self) -> &str;

    /// Memory mapped address of the device
    fn mmap_addr(&self) -> RvAddr;

    /// Memory map size.
    fn mmap_size(&self) -> RvAddr;

    /// Memory map range
    fn mmap_range(&self) -> RangeInclusive<RvAddr> {
        RangeInclusive::new(self.mmap_addr(), self.mmap_addr() + self.mmap_size() - 1)
    }

    /// Return the pending IRQ
    fn pending_irq(&self) -> Option<RvIrq>;

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
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, RvException>;

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
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), RvException>;
}
