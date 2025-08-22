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
use crate::{dma::otp_fc::FuseController, mci::Mci, Sha512Accelerator};
use caliptra_emu_bus::{
    Bus,
    BusError::{self, LoadAccessFault, StoreAccessFault},
    Device, Event, EventData, ReadWriteMemory, Register,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use const_random::const_random;
use std::{rc::Rc, sync::mpsc};

pub type AxiAddr = u64;

const TEST_SRAM_SIZE: usize = 4 * 1024;
const EXTERNAL_TEST_SRAM_SIZE: usize = 1024 * 1024;
const MCU_SRAM_SIZE: usize = 256 * 1024;

pub struct AxiRootBus {
    pub reg: u32,

    pub recovery: RecoveryRegisterInterface,
    event_sender: Option<mpsc::Sender<Event>>,
    pub dma_result: Option<Vec<u32>>,
    pub otp_fc: FuseController,
    pub mci: Mci,
    sha512_acc: Sha512Accelerator,
    pub test_sram: Option<ReadWriteMemory<TEST_SRAM_SIZE>>,
    pub mcu_sram: ReadWriteMemory<MCU_SRAM_SIZE>,
    pub indirect_fifo_status: u32,
    pub use_mcu_recovery_interface: bool,
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
    pub const SS_MCI_END: AxiAddr = Self::SS_MCI_OFFSET + 0x1454; // 0x1454 is last MCI register offset + size
    pub const MCU_SRAM_OFFSET: AxiAddr = Self::SS_MCI_OFFSET + 0xc0_0000;
    pub const MCU_SRAM_END: AxiAddr = Self::MCU_SRAM_OFFSET + 2 * 1024 * 1024 - 1; // the aperture size is 2 MB even though the underlying SRAM may be smaller

    pub const OTC_FC_OFFSET: AxiAddr = (const_random!(u64) & 0xffffffff_00000000) + 0x1000;
    pub const OTC_FC_END: AxiAddr = Self::OTC_FC_OFFSET + 0xfff;

    // Test SRAM is used for testing purposes and is not part of the actual design.
    // An arbitratry offset is chosen to avoid overlap with other peripherals.
    // Test SRAM is only accessible from the Caliptra Core, and is initialized by the emulator.
    pub const TEST_SRAM_OFFSET: AxiAddr = 0x00000000_00500000;
    pub const TEST_SRAM_END: AxiAddr = Self::TEST_SRAM_OFFSET + TEST_SRAM_SIZE as u64;

    // External Test SRAM is used for testing purposes and is not part of the actual design.
    // This SRAM is accessible from the Caliptra Core and the MCU emulators.
    pub const EXTERNAL_TEST_SRAM_OFFSET: AxiAddr = 0x00000000_80000000;
    pub const EXTERNAL_TEST_SRAM_END: AxiAddr =
        Self::EXTERNAL_TEST_SRAM_OFFSET + EXTERNAL_TEST_SRAM_SIZE as u64;

    pub fn new(
        soc_reg: SocRegistersInternal,
        sha512_acc: Sha512Accelerator,
        mci: Mci,
        test_sram_content: Option<&[u8]>,
        use_mcu_recovery_interface: bool,
    ) -> Self {
        let test_sram = if let Some(test_sram_content) = test_sram_content {
            if test_sram_content.len() > TEST_SRAM_SIZE {
                panic!("test_sram_content length exceeds TEST_SRAM_SIZE");
            }
            let mut sram_data = [0u8; TEST_SRAM_SIZE];
            sram_data[..test_sram_content.len()].copy_from_slice(test_sram_content);
            Some(ReadWriteMemory::new_with_data(sram_data))
        } else {
            None
        };
        let mcu_sram = ReadWriteMemory::new();
        Self {
            reg: 0xaabbccdd,
            recovery: RecoveryRegisterInterface::new(),
            otp_fc: FuseController::new(soc_reg),
            mci,
            sha512_acc,
            event_sender: None,
            dma_result: None,
            test_sram,
            mcu_sram,
            indirect_fifo_status: 0,
            use_mcu_recovery_interface,
        }
    }

    pub fn must_schedule(&mut self, addr: AxiAddr) -> bool {
        if self.use_mcu_recovery_interface {
            (matches!(addr, Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END)
                || matches!(
                    addr,
                    Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END
                )
                || matches!(
                    addr,
                    Self::RECOVERY_REGISTER_INTERFACE_OFFSET
                        ..=Self::RECOVERY_REGISTER_INTERFACE_END
                ))
        } else {
            (matches!(addr, Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END)
                || matches!(
                    addr,
                    Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END
                ))
        }
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
            Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END => {
                let addr = addr - Self::EXTERNAL_TEST_SRAM_OFFSET;
                println!("Sending read event for ExternalTestSram");
                if let Some(sender) = self.event_sender.as_mut() {
                    sender
                        .send(Event::new(
                            Device::CaliptraCore,
                            Device::ExternalTestSram,
                            EventData::MemoryRead {
                                start_addr: addr as u32,
                                len,
                            },
                        ))
                        .unwrap();
                }
                Ok(())
            }
            Self::RECOVERY_REGISTER_INTERFACE_OFFSET..=Self::RECOVERY_REGISTER_INTERFACE_END => {
                let addr = addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET;
                if let Some(sender) = self.event_sender.as_mut() {
                    sender
                        .send(Event::new(
                            Device::CaliptraCore,
                            Device::RecoveryIntf,
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
            Self::SHA512_ACC_OFFSET..=Self::SHA512_ACC_END => {
                let addr = ((addr - Self::SHA512_ACC_OFFSET) & 0xffff_ffff) as RvAddr;
                return Bus::read(&mut self.sha512_acc, size, addr);
            }
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
            Self::TEST_SRAM_OFFSET..=Self::TEST_SRAM_END => {
                if let Some(test_sram) = self.test_sram.as_mut() {
                    let addr = (addr - Self::TEST_SRAM_OFFSET) as RvAddr;
                    return Bus::read(test_sram, size, addr);
                } else {
                    return Err(LoadAccessFault);
                }
            }
            Self::MCU_SRAM_OFFSET..=Self::MCU_SRAM_END => {
                let addr = (addr - Self::MCU_SRAM_OFFSET) as RvAddr;
                return Bus::read(&mut self.mcu_sram, size, addr);
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
                if self.use_mcu_recovery_interface {
                    if let Some(sender) = self.event_sender.as_mut() {
                        sender
                            .send(Event::new(
                                Device::CaliptraCore,
                                Device::RecoveryIntf,
                                EventData::MemoryWrite {
                                    start_addr: (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET)
                                        as u32,
                                    data: val.to_le_bytes().to_vec(),
                                },
                            ))
                            .unwrap();
                    }
                    Ok(())
                } else {
                    let addr = (addr - Self::RECOVERY_REGISTER_INTERFACE_OFFSET) as RvAddr;
                    Bus::write(&mut self.recovery, size, addr, val)
                }
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
                // There is nothing responding to this events but we still want to see them happen.
                // This is why we do both and event and a Bus::write
                if !self.use_mcu_recovery_interface {
                    let addr = (addr - Self::MCU_SRAM_OFFSET) as RvAddr;
                    Bus::write(&mut self.mcu_sram, size, addr, val)
                } else {
                    Ok(())
                }
            }
            Self::OTC_FC_OFFSET..=Self::OTC_FC_END => {
                let addr = (addr - Self::OTC_FC_OFFSET) as RvAddr;
                Bus::write(&mut self.otp_fc, size, addr, val)
            }
            Self::SS_MCI_OFFSET..=Self::SS_MCI_END => {
                let addr = (addr - Self::SS_MCI_OFFSET) as RvAddr;
                Bus::write(&mut self.mci, size, addr, val)
            }
            Self::TEST_SRAM_OFFSET..=Self::TEST_SRAM_END => {
                if let Some(test_sram) = self.test_sram.as_mut() {
                    let addr = (addr - Self::TEST_SRAM_OFFSET) as RvAddr;
                    Bus::write(test_sram, size, addr, val)
                } else {
                    Err(StoreAccessFault)
                }
            }
            _ => Err(StoreAccessFault),
        }
    }

    pub fn send_get_recovery_indirect_fifo_status(&mut self) {
        if let Some(sender) = self.event_sender.as_mut() {
            sender
                .send(Event::new(
                    Device::CaliptraCore,
                    Device::RecoveryIntf,
                    EventData::RecoveryFifoStatusRequest,
                ))
                .unwrap();
        }
    }

    pub fn get_recovery_indirect_fifo_status(&self) -> u32 {
        self.indirect_fifo_status
    }

    pub fn incoming_event(&mut self, event: Rc<Event>) {
        self.recovery.incoming_event(event.clone());

        match &event.event {
            EventData::MemoryReadResponse {
                start_addr: _,
                data,
            } => {
                // we only allow read responses from the MCU, ExternalTestSram and RecoveryIntf
                if event.src == Device::MCU
                    || event.src == Device::ExternalTestSram
                    || Device::RecoveryIntf == event.src
                {
                    self.dma_result = Some(words_from_bytes_be_vec(&data.clone()));
                }
            }
            EventData::RecoveryFifoStatusResponse { status } => {
                self.indirect_fifo_status = *status;
            }
            _ => {}
        }
    }

    pub fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.event_sender = Some(sender.clone());
        self.recovery.register_outgoing_events(sender);
    }
}
