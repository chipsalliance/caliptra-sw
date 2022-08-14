/*++

Licensed under the Apache-2.0 license.

File Name:

    fake_bus.rs

Abstract:

    File contains code for a fake implementation of the Bus trait.

--*/
use caliptra_emu_types::{RvAddr, RvData, RvSize};

use crate::{testing::Log, Bus, BusError};
use std::fmt::Write;

/// A Bus implementation that logs all calls, and allows the user to override
/// the return value of the methods.
///
/// # Example
///
/// ```
/// use caliptra_emu_bus::{Bus, testing::FakeBus};
/// use caliptra_emu_types::RvSize;
///
/// let mut fake_bus = FakeBus::new();
/// fake_bus.read_result = Ok(35);
/// assert_eq!(fake_bus.read(RvSize::HalfWord, 0xdeadcafe), Ok(35));
/// assert_eq!("read(RvSize::HalfWord, 0xdeadcafe)\n", fake_bus.log.take());
/// ```
pub struct FakeBus {
    pub log: Log,
    pub read_result: Result<RvData, crate::BusError>,
    pub write_result: Result<(), crate::BusError>,
}
impl FakeBus {
    pub fn new() -> Self {
        Self {
            log: Log::new(),
            read_result: Ok(0),
            write_result: Ok(()),
        }
    }
}
impl Bus for FakeBus {
    fn read(&self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        writeln!(self.log.w(), "read(RvSize::{size:?}, {addr:#x})").unwrap();
        self.read_result
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        writeln!(self.log.w(), "write(RvSize::{size:?}, {addr:#x}, {val:#x})").unwrap();
        self.write_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_bus() {
        let mut fake_bus = FakeBus::new();

        assert_eq!(fake_bus.read(RvSize::HalfWord, 0xdeadcafe), Ok(0));
        assert_eq!("read(RvSize::HalfWord, 0xdeadcafe)\n", fake_bus.log.take());

        assert_eq!(fake_bus.write(RvSize::Word, 0xf00dcafe, 0x537), Ok(()));
        assert_eq!(
            "write(RvSize::Word, 0xf00dcafe, 0x537)\n",
            fake_bus.log.take()
        );

        fake_bus.read_result = Err(BusError::LoadAccessFault);
        assert_eq!(
            fake_bus.read(RvSize::Byte, 0x12345678),
            Err(BusError::LoadAccessFault)
        );
        assert_eq!("read(RvSize::Byte, 0x12345678)\n", fake_bus.log.take());

        fake_bus.write_result = Err(BusError::StoreAddrMisaligned);
        assert_eq!(
            fake_bus.write(RvSize::Word, 0x131, 0x1),
            Err(BusError::StoreAddrMisaligned)
        );
        assert_eq!("write(RvSize::Word, 0x131, 0x1)\n", fake_bus.log.take());
    }
}
