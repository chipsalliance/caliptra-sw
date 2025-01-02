/*++

Licensed under the Apache-2.0 license.

File Name:

    axi_root_bus.rs

Abstract:

    File contains the axi root bus peripheral.

--*/

use caliptra_emu_bus::{BusError, BusError::LoadAccessFault, BusError::StoreAccessFault, Register};
use caliptra_emu_types::{RvData, RvSize};

pub type AxiAddr = u64;

pub struct AxiRootBus {
    pub reg: u32,
}

impl AxiRootBus {
    const TEST_REG_OFFSET: AxiAddr = 0xaa00;

    pub fn new() -> Self {
        Self { reg: 0xaabbccdd }
    }

    pub fn read(&mut self, size: RvSize, addr: AxiAddr) -> Result<RvData, BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::read(&self.reg, size),
            _ => {}
        }

        Err(LoadAccessFault)
    }

    pub fn write(&mut self, size: RvSize, addr: AxiAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::write(&mut self.reg, size, val),
            _ => {}
        }

        Err(StoreAccessFault)
    }
}
