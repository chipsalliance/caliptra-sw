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

use crate::dma::otp_fc::FuseController;
use crate::dma::recovery::RecoveryRegisterInterface;
use crate::SocRegistersInternal;

pub struct AxiRootBus {
    pub reg: u32,

    pub recovery: RecoveryRegisterInterface,

    pub otp_fc: FuseController,
}

impl AxiRootBus {
    const TEST_REG_OFFSET: AxiAddr = 0xaa00;
    pub const RECOVERY_REGISTER_INTERFACE_OFFSET: AxiAddr = 0xf_00000000;
    pub const RECOVERY_REGISTER_INTERFACE_END: AxiAddr = 0xf_000000ff;

    pub const OTC_FC_OFFSET: AxiAddr = 0xf_00001000;
    pub const OTC_FC_END: AxiAddr = 0xf_00001fff;

    pub fn new(soc_reg: SocRegistersInternal) -> Self {
        Self {
            reg: 0xaabbccdd,
            recovery: RecoveryRegisterInterface::new(),
            otp_fc: FuseController::new(soc_reg),
        }
    }

    pub fn read(&mut self, size: RvSize, addr: AxiAddr) -> Result<RvData, BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::read(&self.reg, size),
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                return Bus::read(&mut self.recovery, size, addr);
            }
            Self::OTC_FC_OFFSET..=Self::OTC_FC_END => {
                let addr = (addr - Self::OTC_FC_OFFSET) as RvAddr;
                return Bus::read(&mut self.otp_fc, size, addr);
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
            Self::OTC_FC_OFFSET..=Self::OTC_FC_END => {
                let addr = (addr - Self::OTC_FC_OFFSET) as RvAddr;
                return Bus::write(&mut self.otp_fc, size, addr, val);
            }
            _ => {}
        }

        Err(StoreAccessFault)
    }
}
