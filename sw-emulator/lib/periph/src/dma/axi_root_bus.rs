/*++

Licensed under the Apache-2.0 license.

File Name:

    axi_root_bus.rs

Abstract:

    File contains the axi root bus peripheral.

--*/

use crate::dma::recovery::RecoveryRegisterInterface;
use crate::helpers::words_from_bytes_be_vec;
use crate::SocRegistersInternal;
use crate::{dma::otp_fc::FuseController, Sha512Accelerator};
use caliptra_emu_bus::{
    Bus,
    BusError::{self, LoadAccessFault, StoreAccessFault},
    Device, Event, EventData, Register,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use const_random::const_random;
use std::{rc::Rc, sync::mpsc};

pub type AxiAddr = u64;

use super::mci::Mci;

pub struct AxiRootBus {
    pub reg: u32,

    pub recovery: RecoveryRegisterInterface,
    event_sender: Option<mpsc::Sender<Event>>,
    pub dma_result: Option<Vec<u32>>,
    pub otp_fc: FuseController,
    pub mci: Mci,
    sha512_acc: Sha512Accelerator,
}

impl AxiRootBus {
    const SHA512_ACC_OFFSET: AxiAddr = 0x3002_1000;
    const SHA512_ACC_END: AxiAddr = 0x3002_10ff;
    const TEST_REG_OFFSET: AxiAddr = 0xaa00;
    // ROM and Runtime code should not depend on the exact values of these.
    pub const RECOVERY_REGISTER_INTERFACE_OFFSET: AxiAddr =
        const_random!(u64) & 0xffffffff_00000000;
    pub const RECOVERY_REGISTER_INTERFACE_END: AxiAddr =
        Self::RECOVERY_REGISTER_INTERFACE_OFFSET + 0xff;
    pub const SS_MCI_OFFSET: AxiAddr = const_random!(u64) & 0xffffffff_00000000;
    pub const SS_MCI_END: AxiAddr = Self::SS_MCI_OFFSET + 0xfff;
    pub const MCU_SRAM_OFFSET: AxiAddr = Self::SS_MCI_OFFSET + 0x20_0000;
    pub const MCU_SRAM_END: AxiAddr = Self::MCU_SRAM_OFFSET + 2 * 1024 * 1024 - 1; // the aperture size is 2 MB even though the underlying SRAM may be smaller

    pub const OTC_FC_OFFSET: AxiAddr = (const_random!(u64) & 0xffffffff_00000000) + 0x1000;
    pub const OTC_FC_END: AxiAddr = Self::OTC_FC_OFFSET + 0xfff;

    pub fn new(
        soc_reg: SocRegistersInternal,
        sha512_acc: Sha512Accelerator,
        prod_dbg_unlock_keypairs: Vec<(&[u8; 96], &[u8; 2592])>,
    ) -> Self {
        Self {
            reg: 0xaabbccdd,
            recovery: RecoveryRegisterInterface::new(),
            otp_fc: FuseController::new(soc_reg),
            mci: Mci::new(prod_dbg_unlock_keypairs),
            sha512_acc,
            event_sender: None,
            dma_result: None,
        }
    }

    pub fn must_schedule(&mut self, addr: AxiAddr) -> bool {
        matches!(addr, Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END)
    }

    pub fn schedule_read(&mut self, addr: AxiAddr, len: u32) -> Result<(), BusError> {
        if self.dma_result.is_some() {
            println!("Cannot schedule read if previous DMA result has not been consumed");
            return Err(BusError::LoadAccessFault);
        }
        match addr {
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => {
                let addr = addr - Self::MCU_SRAM_OFFSET;
                if let Some(sender) = self.event_sender.as_mut() {
                    sender
                        .send(Event::new(
                            Device::CaliptraCore,
                            Device::MCU,
                            EventData::MemoryRead {
                                start_addr: addr as u32,
                                len,
                            },
                        ))
                        .unwrap();
                }
                Ok(())
            }
            _ => Err(BusError::LoadAccessFault),
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
            Self::SS_MCI_OFFSET..=Self::SS_MCI_END => {
                let addr = (addr - Self::SS_MCI_OFFSET) as RvAddr;
                return Bus::read(&mut self.mci, size, addr);
            }
            _ => {}
        };

        Err(LoadAccessFault)
    }

    pub fn write(&mut self, size: RvSize, addr: AxiAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::SHA512_ACC_OFFSET..=Self::SHA512_ACC_END => self.sha512_acc.write(
                size,
                ((addr - Self::SHA512_ACC_OFFSET) & 0xffff_ffff) as u32,
                val,
            ),
            Self::TEST_REG_OFFSET => Register::write(&mut self.reg, size, val),
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                Bus::write(&mut self.recovery, size, addr, val)
            }
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => {
                if let Some(sender) = self.event_sender.as_mut() {
                    sender
                        .send(Event::new(
                            Device::CaliptraCore,
                            Device::MCU,
                            EventData::MemoryWrite {
                                start_addr: (addr - Self::MCU_SRAM_OFFSET) as u32,
                                data: val.to_le_bytes().to_vec(),
                            },
                        ))
                        .unwrap();
                }
                Ok(())
            }
            Self::OTC_FC_OFFSET..=Self::OTC_FC_END => {
                let addr = (addr - Self::OTC_FC_OFFSET) as RvAddr;
                Bus::write(&mut self.otp_fc, size, addr, val)
            }
            Self::SS_MCI_OFFSET..=Self::SS_MCI_END => {
                let addr = (addr - Self::SS_MCI_OFFSET) as RvAddr;
                Bus::write(&mut self.mci, size, addr, val)
            }
            _ => Err(StoreAccessFault),
        }
    }

    pub fn incoming_event(&mut self, event: Rc<Event>) {
        self.recovery.incoming_event(event.clone());
        if let EventData::MemoryReadResponse {
            start_addr: _,
            data,
        } = &event.event
        {
            // we only allow read responses from the MCU
            if event.src == Device::MCU {
                self.dma_result = Some(words_from_bytes_be_vec(&data.clone()));
            }
        }
    }

    pub fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.event_sender = Some(sender.clone());
        self.recovery.register_outgoing_events(sender);
    }
}
