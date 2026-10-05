/*++

Licensed under the Apache-2.0 license.

File Name:

    axi_root_bus.rs

Abstract:

    File contains the axi root bus peripheral.

--*/

use crate::dma::recovery::RecoveryRegisterInterface;
use crate::helpers::words_from_bytes_le_vec;
use crate::SocRegistersInternal;
use crate::{dma::otp_fc::FuseController, mci::Mci, Sha512Accelerator};
use caliptra_emu_bus::{
    Bus,
    BusError::{self, LoadAccessFault, StoreAccessFault},
    Device, Event, EventData, ReadWriteMemory, Register,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use const_random::const_random;
use std::env;
use std::sync::LazyLock;
use std::{rc::Rc, sync::mpsc};

pub type AxiAddr = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubsystemAddresses {
    pub caliptra: AxiAddr,
    pub mci: AxiAddr,
    pub recovery: AxiAddr,
    pub otp_fc: AxiAddr,
    pub uds_seed: AxiAddr,
}

impl Default for SubsystemAddresses {
    fn default() -> Self {
        let otp_fc = AxiRootBus::OTC_FC_OFFSET;
        Self {
            caliptra: 0x3000_0000,
            mci: AxiRootBus::ss_mci_offset(),
            recovery: AxiRootBus::RECOVERY_REGISTER_INTERFACE_OFFSET,
            otp_fc,
            uds_seed: otp_fc + 0x800,
        }
    }
}

// Large enough to stage firmware images bigger than the DMA's 1 MiB
// per-transfer limit, so tests can exercise multi-transfer image hashing.
const TEST_SRAM_SIZE: usize = 4 * 1024 * 1024;
const EXTERNAL_TEST_SRAM_SIZE: usize = 1024 * 1024;
const MCU_SRAM_SIZE: usize = 512 * 1024;

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
    enable_external_soc_dma: bool,
    addresses: SubsystemAddresses,
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

    pub fn ss_mci_offset() -> AxiAddr {
        *SS_MCI_OFFSET
    }

    pub fn ss_mci_end() -> AxiAddr {
        *SS_MCI_OFFSET + 0x1454 // 0x1454 is last MCI register offset + size
    }
    pub fn mcu_sram_offset() -> AxiAddr {
        *SS_MCI_OFFSET + 0xc0_0000
    }
    pub fn mcu_sram_end() -> AxiAddr {
        Self::mcu_sram_offset() + MCU_SRAM_SIZE as u64 - 1
    }
    pub fn mcu_mbox0_sram_offset() -> AxiAddr {
        *SS_MCI_OFFSET + 0x40_0000
    }
    pub fn mcu_mbox0_sram_end() -> AxiAddr {
        Self::mcu_mbox0_sram_offset() + 0x20_0000 - 1
    }
    pub fn mcu_mbox1_sram_offset() -> AxiAddr {
        *SS_MCI_OFFSET + 0x80_0000
    }
    pub fn mcu_mbox1_sram_end() -> AxiAddr {
        Self::mcu_mbox1_sram_offset() + 0x20_0000 - 1
    }

    fn configured_ss_mci_end(&self) -> AxiAddr {
        self.addresses.mci + 0x1454
    }

    fn configured_mcu_sram_offset(&self) -> AxiAddr {
        self.addresses.mci + 0xc0_0000
    }

    fn configured_mcu_sram_end(&self) -> AxiAddr {
        self.configured_mcu_sram_offset() + MCU_SRAM_SIZE as u64 - 1
    }

    fn configured_mcu_mbox0_sram_offset(&self) -> AxiAddr {
        self.addresses.mci + 0x40_0000
    }

    fn configured_mcu_mbox0_sram_end(&self) -> AxiAddr {
        self.configured_mcu_mbox0_sram_offset() + 0x20_0000 - 1
    }

    fn configured_mcu_mbox1_sram_offset(&self) -> AxiAddr {
        self.addresses.mci + 0x80_0000
    }

    fn configured_mcu_mbox1_sram_end(&self) -> AxiAddr {
        self.configured_mcu_mbox1_sram_offset() + 0x20_0000 - 1
    }

    fn recovery_end(&self) -> AxiAddr {
        self.addresses.recovery + 0xff
    }

    fn otp_fc_end(&self) -> AxiAddr {
        self.addresses.otp_fc + 0xfff
    }

    fn is_internal(&self, addr: AxiAddr) -> bool {
        matches!(addr, Self::SHA512_ACC_OFFSET..=Self::SHA512_ACC_END)
            || addr == Self::TEST_REG_OFFSET
            || (self.addresses.recovery..=self.recovery_end()).contains(&addr)
            || (self.addresses.otp_fc..=self.otp_fc_end()).contains(&addr)
            || matches!(addr, Self::TEST_SRAM_OFFSET..=Self::TEST_SRAM_END)
            || matches!(
                addr,
                Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END
            )
            || (self.addresses.mci..=self.configured_mcu_sram_end()).contains(&addr)
    }

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
        enable_external_soc_dma: bool,
        addresses: SubsystemAddresses,
    ) -> Self {
        let test_sram = if let Some(test_sram_content) = test_sram_content {
            if test_sram_content.len() > TEST_SRAM_SIZE {
                panic!("test_sram_content length exceeds TEST_SRAM_SIZE");
            }
            // Allocate zeroed (heap-backed, so a large TEST_SRAM_SIZE does not
            // overflow the stack) and copy the caller's content into the front.
            let mut sram = ReadWriteMemory::new();
            sram.data_mut()[..test_sram_content.len()].copy_from_slice(test_sram_content);
            Some(sram)
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
            enable_external_soc_dma,
            addresses,
        }
    }

    pub fn must_schedule(&mut self, addr: AxiAddr) -> bool {
        if self.use_mcu_recovery_interface {
            (addr >= self.configured_mcu_sram_offset() && addr <= self.configured_mcu_sram_end())
                || matches!(
                    addr,
                    Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END
                )
                || (addr >= self.configured_mcu_mbox0_sram_offset()
                    && addr <= self.configured_mcu_mbox0_sram_end())
                || (addr >= self.configured_mcu_mbox1_sram_offset()
                    && addr <= self.configured_mcu_mbox1_sram_end())
                || (self.addresses.recovery..=self.recovery_end()).contains(&addr)
                || (self.enable_external_soc_dma && !self.is_internal(addr))
        } else {
            (addr >= self.configured_mcu_sram_offset() && addr <= self.configured_mcu_sram_end())
                || (addr >= self.configured_mcu_mbox0_sram_offset()
                    && addr <= self.configured_mcu_mbox0_sram_end())
                || (addr >= self.configured_mcu_mbox1_sram_offset()
                    && addr <= self.configured_mcu_mbox1_sram_end())
                || (Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END).contains(&addr)
                || (self.enable_external_soc_dma && !self.is_internal(addr))
        }
    }

    pub fn schedule_read(&mut self, addr: AxiAddr, len: u32) -> Result<(), BusError> {
        if self.dma_result.is_some() {
            println!("Cannot schedule read if previous DMA result has not been consumed");
            return Err(BusError::LoadAccessFault);
        }
        if (self.configured_mcu_sram_offset()..=self.configured_mcu_sram_end()).contains(&addr) {
            let addr = addr - self.configured_mcu_sram_offset();
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
        } else if (self.configured_mcu_mbox0_sram_offset()..=self.configured_mcu_mbox0_sram_end())
            .contains(&addr)
        {
            let addr = addr - self.configured_mcu_mbox0_sram_offset();
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::McuMbox0Sram,
                        EventData::MemoryRead {
                            start_addr: addr as u32,
                            len,
                        },
                    ))
                    .unwrap();
            }
            Ok(())
        } else if (self.configured_mcu_mbox1_sram_offset()..=self.configured_mcu_mbox1_sram_end())
            .contains(&addr)
        {
            let addr = addr - self.configured_mcu_mbox1_sram_offset();
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::McuMbox1Sram,
                        EventData::MemoryRead {
                            start_addr: addr as u32,
                            len,
                        },
                    ))
                    .unwrap();
            }
            Ok(())
        } else if (Self::EXTERNAL_TEST_SRAM_OFFSET..=Self::EXTERNAL_TEST_SRAM_END).contains(&addr) {
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
        } else if (self.addresses.recovery..=self.recovery_end()).contains(&addr) {
            let addr = addr - self.addresses.recovery;
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
        } else {
            if !self.enable_external_soc_dma {
                return Err(LoadAccessFault);
            }
            let start_addr = u32::try_from(addr).map_err(|_| LoadAccessFault)?;
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::ExternalSoc,
                        EventData::MemoryRead { start_addr, len },
                    ))
                    .unwrap();
            }
            Ok(())
        }
    }

    pub fn read(&mut self, size: RvSize, addr: AxiAddr) -> Result<RvData, BusError> {
        match addr {
            Self::SHA512_ACC_OFFSET..=Self::SHA512_ACC_END => {
                let addr = ((addr - Self::SHA512_ACC_OFFSET) & 0xffff_ffff) as RvAddr;
                return Bus::read(&mut self.sha512_acc, size, addr);
            }
            Self::TEST_REG_OFFSET => return Register::read(&self.reg, size),
            addr if (self.addresses.recovery..=self.recovery_end()).contains(&addr) => {
                let addr = (addr - self.addresses.recovery) as RvAddr;
                return Bus::read(&mut self.recovery, size, addr);
            }
            addr if (self.addresses.otp_fc..=self.otp_fc_end()).contains(&addr) => {
                let addr = (addr - self.addresses.otp_fc) as RvAddr;
                return Bus::read(&mut self.otp_fc, size, addr);
            }
            Self::TEST_SRAM_OFFSET..=Self::TEST_SRAM_END => {
                if let Some(test_sram) = self.test_sram.as_mut() {
                    let addr = (addr - Self::TEST_SRAM_OFFSET) as RvAddr;
                    return Bus::read(test_sram, size, addr);
                } else {
                    return Err(LoadAccessFault);
                }
            }
            _ => {}
        };

        if (self.configured_mcu_sram_offset()..=self.configured_mcu_sram_end()).contains(&addr) {
            let addr = (addr - self.configured_mcu_sram_offset()) as RvAddr;
            return Bus::read(&mut self.mcu_sram, size, addr);
        } else if (self.addresses.mci..=self.configured_ss_mci_end()).contains(&addr) {
            let addr = (addr - self.addresses.mci) as RvAddr;
            return Bus::read(&mut self.mci, size, addr);
        }

        Err(LoadAccessFault)
    }

    pub fn write(&mut self, size: RvSize, addr: AxiAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::SHA512_ACC_OFFSET..=Self::SHA512_ACC_END => {
                return self.sha512_acc.write(
                    size,
                    ((addr - Self::SHA512_ACC_OFFSET) & 0xffff_ffff) as u32,
                    val,
                )
            }
            Self::TEST_REG_OFFSET => return Register::write(&mut self.reg, size, val),
            addr if (self.addresses.recovery..=self.recovery_end()).contains(&addr) => {
                if self.use_mcu_recovery_interface {
                    if let Some(sender) = self.event_sender.as_mut() {
                        sender
                            .send(Event::new(
                                Device::CaliptraCore,
                                Device::RecoveryIntf,
                                EventData::MemoryWrite {
                                    start_addr: (addr - self.addresses.recovery) as u32,
                                    data: val.to_le_bytes().to_vec(),
                                },
                            ))
                            .unwrap();
                    }
                    return Ok(());
                } else {
                    let addr = (addr - self.addresses.recovery) as RvAddr;
                    return Bus::write(&mut self.recovery, size, addr, val);
                }
            }
            addr if (self.addresses.otp_fc..=self.otp_fc_end()).contains(&addr) => {
                let addr = (addr - self.addresses.otp_fc) as RvAddr;
                return Bus::write(&mut self.otp_fc, size, addr, val);
            }
            Self::TEST_SRAM_OFFSET..=Self::TEST_SRAM_END => {
                if let Some(test_sram) = self.test_sram.as_mut() {
                    let addr = (addr - Self::TEST_SRAM_OFFSET) as RvAddr;
                    return Bus::write(test_sram, size, addr, val);
                } else {
                    return Err(StoreAccessFault);
                }
            }
            _ => {}
        };
        if (self.configured_mcu_sram_offset()..=self.configured_mcu_sram_end()).contains(&addr) {
            let mcu_sram_offset = self.configured_mcu_sram_offset();
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::MCU,
                        EventData::MemoryWrite {
                            start_addr: (addr - mcu_sram_offset) as u32,
                            data: val.to_le_bytes().to_vec(),
                        },
                    ))
                    .unwrap();
            }
            // There is nothing responding to this events but we still want to see them happen.
            // This is why we do both and event and a Bus::write
            if !self.use_mcu_recovery_interface {
                let addr = (addr - mcu_sram_offset) as RvAddr;
                return Bus::write(&mut self.mcu_sram, size, addr, val);
            } else {
                return Ok(());
            }
        } else if (self.configured_mcu_mbox0_sram_offset()..=self.configured_mcu_mbox0_sram_end())
            .contains(&addr)
        {
            let mcu_mbox0_sram_offset = self.configured_mcu_mbox0_sram_offset();
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::McuMbox0Sram,
                        EventData::MemoryWrite {
                            start_addr: (addr - mcu_mbox0_sram_offset) as u32,
                            data: val.to_le_bytes().to_vec(),
                        },
                    ))
                    .unwrap();
            }
            // There is nothing responding to this events but we still want to see them happen.
            // This is why we do both and event and a Bus::write
            return Ok(());
        } else if (self.configured_mcu_mbox1_sram_offset()..=self.configured_mcu_mbox1_sram_end())
            .contains(&addr)
        {
            let mcu_mbox1_sram_offset = self.configured_mcu_mbox1_sram_offset();
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::McuMbox1Sram,
                        EventData::MemoryWrite {
                            start_addr: (addr - mcu_mbox1_sram_offset) as u32,
                            data: val.to_le_bytes().to_vec(),
                        },
                    ))
                    .unwrap();
            }
            // There is nothing responding to this events but we still want to see them happen.
            // This is why we do both and event and a Bus::write
            return Ok(());
        } else if (self.addresses.mci..=self.configured_ss_mci_end()).contains(&addr) {
            let addr = (addr - self.addresses.mci) as RvAddr;
            return Bus::write(&mut self.mci, size, addr, val);
        } else {
            if !self.enable_external_soc_dma {
                return Err(StoreAccessFault);
            }
            let start_addr = u32::try_from(addr).map_err(|_| StoreAccessFault)?;
            if let Some(sender) = self.event_sender.as_mut() {
                sender
                    .send(Event::new(
                        Device::CaliptraCore,
                        Device::ExternalSoc,
                        EventData::MemoryWrite {
                            start_addr,
                            data: val.to_le_bytes().to_vec(),
                        },
                    ))
                    .unwrap();
            }
            return Ok(());
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
            } if event.src == Device::MCU
                || event.src == Device::ExternalTestSram
                || Device::RecoveryIntf == event.src
                || event.src == Device::ExternalSoc =>
            {
                self.dma_result = Some(words_from_bytes_le_vec(&data.clone()));
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

static SS_MCI_OFFSET: LazyLock<AxiAddr> = LazyLock::new(|| {
    if let Ok(s) = env::var("CPTRA_EMULATOR_SS_MCI_OFFSET") {
        parse_u64(&s)
    } else {
        const_random!(u64) & 0xffffffff_00000000
    }
});
fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap()
    } else {
        s.parse::<u64>().unwrap()
    }
}
