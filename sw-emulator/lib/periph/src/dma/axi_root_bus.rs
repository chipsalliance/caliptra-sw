/*++

Licensed under the Apache-2.0 license.

File Name:

    axi_root_bus.rs

Abstract:

    File contains the axi root bus peripheral.

--*/

use crate::dma::recovery::RecoveryRegisterInterface;
use caliptra_emu_bus::{
    Bus,
    BusError::{self, LoadAccessFault, StoreAccessFault},
    Device, Event, EventData, Register,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use const_random::const_random;
use std::{rc::Rc, sync::mpsc};

pub type AxiAddr = u64;

pub struct AxiRootBus {
    pub reg: u32,

    pub recovery: RecoveryRegisterInterface,
    event_sender: Option<mpsc::Sender<Event>>,
    pub dma_result: Option<Vec<u8>>,
}

impl Default for AxiRootBus {
    fn default() -> Self {
        Self::new()
    }
}

impl AxiRootBus {
    const TEST_REG_OFFSET: AxiAddr = 0xaa00;
    // ROM and Runtime code should not depend on the exact values of these.
    pub const RECOVERY_REGISTER_INTERFACE_OFFSET: AxiAddr =
        const_random!(u64) & 0xffffffff_00000000;
    pub const RECOVERY_REGISTER_INTERFACE_END: AxiAddr =
        Self::RECOVERY_REGISTER_INTERFACE_OFFSET + 0xff;
    pub const MCI_OFFSET: AxiAddr = const_random!(u64) & 0xffffffff_00000000;
    pub const MCU_SRAM_OFFSET: AxiAddr = Self::MCI_OFFSET + 0x20_0000;
    pub const MCU_SRAM_END: AxiAddr = Self::MCU_SRAM_OFFSET + 2 * 1024 * 1024 - 1; // the aperture size is 2 MB even though the underlying SRAM may be smaller
    pub const MCI_END: AxiAddr = Self::MCU_SRAM_END;

    pub fn new() -> Self {
        Self {
            reg: 0xaabbccdd,
            recovery: RecoveryRegisterInterface::new(),
            event_sender: None,
            dma_result: None,
        }
    }

    pub fn must_schedule(&mut self, addr: AxiAddr) -> bool {
        match addr {
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => true,
            _ => false,
        }
    }

    pub fn schedule_read(&mut self, addr: AxiAddr, len: u32) -> Result<(), BusError> {
        if self.dma_result.is_some() {
            println!("Cannot schedule read if previous DMA result has not been consumed");
            return Err(BusError::LoadAccessFault);
        }
        match addr {
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => {
                self.event_sender.as_mut().map(|sender| {
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
                });
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
            _ => {}
        };

        Err(LoadAccessFault)
    }

    pub fn write(&mut self, size: RvSize, addr: AxiAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::TEST_REG_OFFSET => return Register::write(&mut self.reg, size, val),
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                Bus::write(&mut self.recovery, size, addr, val)
            }
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => {
                self.event_sender.as_mut().map(|sender| {
                    sender
                        .send(Event::new(
                            Device::CaliptraCore,
                            Device::MCU,
                            EventData::MemoryWrite {
                                start_addr: addr as u32,
                                data: val.to_le_bytes().to_vec(),
                            },
                        ))
                        .unwrap();
                });
                Ok(())
            }
            _ => Err(StoreAccessFault),
        }
    }

    pub fn incoming_event(&mut self, event: Rc<Event>) {
        self.recovery.incoming_event(event.clone());
        match &event.event {
            EventData::MemoryReadResponse {
                start_addr: _,
                data,
            } => {
                // we only access read responses from the MCU
                if event.src == Device::MCU {
                    self.dma_result = Some(data.clone());
                }
            }
            _ => {}
        }
    }

    pub fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.event_sender = Some(sender.clone());
        self.recovery.register_outgoing_events(sender);
    }
}
