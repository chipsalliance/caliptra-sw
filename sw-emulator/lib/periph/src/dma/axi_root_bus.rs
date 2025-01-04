/*++

Licensed under the Apache-2.0 license.

File Name:

    axi_root_bus.rs

Abstract:

    File contains the axi root bus peripheral.

--*/

use caliptra_emu_bus::{
    Bus, BusError, BusError::LoadAccessFault, BusError::StoreAccessFault, Register,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

pub type AxiAddr = u64;

use crate::dma::recovery::RecoveryRegisterInterface;

pub struct AxiRootBus {
    pub reg: u32,

    pub recovery: RecoveryRegisterInterface,
}

impl Default for AxiRootBus {
    fn default() -> Self {
        Self::new()
    }
}

impl AxiRootBus {
    const TEST_REG_OFFSET: AxiAddr = 0xaa00;
    pub const RECOVERY_REGISTER_INTERFACE_OFFSET: AxiAddr = 0xf_00000000;
    pub const RECOVERY_REGISTER_INTERFACE_END: AxiAddr = 0xf_000000ff;

    pub fn new() -> Self {
        Self {
            reg: 0xaabbccdd,
            recovery: RecoveryRegisterInterface::new(),
        }
    }

    pub fn read(&mut self, size: RvSize, addr: AxiAddr) -> Result<RvData, BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::read(&self.reg, size),
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                return Bus::read(&mut self.recovery, size, addr);
            }
            _ => {}
        };

        Err(LoadAccessFault)
    }

    pub fn write(&mut self, size: RvSize, addr: AxiAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::write(&mut self.reg, size, val),
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                return Bus::write(&mut self.recovery, size, addr, val);
            }
            _ => {}
        }

        Err(StoreAccessFault)
    }
}
