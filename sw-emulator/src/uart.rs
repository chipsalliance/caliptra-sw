/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains UART device implementation.

--*/

use crate::device::Device;
use crate::exception::RvException;
use crate::types::{RvAddr, RvData, RvIrq, RvSize};

pub struct Uart {
    name: String,
    mmap_addr: RvAddr,
    mmap_size: RvAddr,
    bit_rate: u8,
    data_bits: u8,
    stop_bits: u8,
}

impl Uart {
    /// Bit Rate Register
    const ADDR_BIT_RATE: RvAddr = 0x00000010;

    /// Data Bits Register
    const ADDR_DATA_BITS: RvAddr = 0x00000011;

    /// Stop Bits Register
    const ADDR_STOP_BITS: RvAddr = 0x00000012;

    /// Transmit status Register
    const ADDR_TX_STATUS: RvAddr = 0x00000040;

    /// Transmit Data Register
    const ADDR_TX_DATA: RvAddr = 0x00000041;

    pub fn new(name: &str, addr: RvAddr) -> Self {
        Self {
            name: String::from(name),
            mmap_addr: addr,
            mmap_size: 256,
            bit_rate: 0,
            data_bits: 8,
            stop_bits: 1,
        }
    }
}

impl Device for Uart {
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
            (RvSize::Byte, Uart::ADDR_BIT_RATE) => Ok(self.bit_rate as RvData),
            (RvSize::Byte, Uart::ADDR_DATA_BITS) => Ok(self.data_bits as RvData),
            (RvSize::Byte, Uart::ADDR_STOP_BITS) => Ok(self.stop_bits as RvData),
            (RvSize::Byte, Uart::ADDR_TX_STATUS) => Ok(1),
            _ => Err(RvException::load_access_fault(addr)),
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
    /// * `RvException` - Exception with cause `RvExceptionCause::StoreAccessFault`
    ///                   or `RvExceptionCause::StoreAddrMisaligned`
    fn write(&mut self, size: RvSize, addr: RvAddr, value: RvData) -> Result<(), RvException> {
        match (size, addr) {
            (RvSize::Byte, Uart::ADDR_BIT_RATE) => self.bit_rate = value as u8,
            (RvSize::Byte, Uart::ADDR_DATA_BITS) => self.data_bits = value as u8,
            (RvSize::Byte, Uart::ADDR_STOP_BITS) => self.stop_bits = value as u8,
            (RvSize::Byte, Uart::ADDR_TX_DATA) => print!("{}", value as u8 as char),
            _ => Err(RvException::store_access_fault(addr))?,
        }

        Ok(())
    }
}
