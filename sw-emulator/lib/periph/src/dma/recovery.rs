/*++

Licensed under the Apache-2.0 license.

File Name:

   recovery.rs

Abstract:

   File contains the recovery register interface peripheral

--*/

use caliptra_emu_bus::{BusError, ReadOnlyRegister, ReadWriteRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvData, RvSize};
use std::mem;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

register_bitfields! [
    u32,

    /// Recovery Control
    RecoveryControl [
        CMS OFFSET(0) NUMBITS(8) [],
        IMAGE_SELECTION OFFSET(8) NUMBITS(8) [
            NoOperation = 0,
            RecoveryFromCms = 1,
            RecoveryStoredOnDevice = 2,
            // Other bits are reserved
        ],
        ACTIVATE_RECOVERY_IMAGE OFFSET(16) NUMBITS(8) [
            DoNotActivate = 0,
            Activate = 0xf,
        ],
    ],

    /// Recovery Status
    RecoveryStatus [
        DEVICE_RECOVERY OFFSET(0) NUMBITS(8) [
            NotInRecovery = 0x0,
            AwaitingRecoveryImage = 0x1,
            BootingRecoveryImage = 0x2,
            RecoverySuccesfull = 0x3,
            RecoveryFailed = 0xc,
            AuthenticationError = 0xd,
            ErrorEnteringRecovery = 0xe,
            InvalidComponentAddressSpace = 0xf,
            // 0x10-ff Reserved
        ],
        VENDOR_SPECIFIC OFFSET(8) NUMBITS(8) [],
    ],

    /// HW Status
    HwStatus [
        HW_STATUS OFFSET(0) NUMBITS(8) [
            TemperatureCritial = 0x0,
            HardwareSoftError = 0x1,
            HardwareFatalError = 0x2,
        ],
        VENDOR_HW_STATUS OFFSET(8) NUMBITS(8) [],
        // 0x00-0x7e: 0 to 126 C
        // 0x7f: 127 C or higher
        // 0x80: no temperature data, or data is older than 5 seconds
        // 0x81: temperature sensor failure
        // 0x82-0x83: reserved
        // 0xc4: -60 C or lower
        // 0xc5-0xff: -1 to -59 C (in twoʼs complement)
        COMPOSITE_TEMP OFFSET(16) NUMBITS(8) [],
    ],

    /// Indirect FIFO Control
    IndirectCtrl [
        CMS OFFSET(0) NUMBITS(8),
        RESET OFFSET(8) NUMBITS(1),
    ],

    /// Indirect FIFO Status
    IndirectStatus [
        FIFO_EMPTY OFFSET(0) NUMBITS(1) [],
        FIFO_FULL OFFSET(1) NUMBITS(1) [],
        REGION_TYPE OFFSET(8) NUMBITS(3) [
            CodeSpaceRecovery = 0, // Write Only
            LogWithDebugFormat = 1, // Read Only
            VendorDefinedRegionWriteOnly = 4,
            VendorDefinedRegionReadOnly = 5,
            UnsupportedRegion = 7,
        ],
    ],
];

/// Recovery register interface
#[derive(Bus)]
pub struct RecoveryRegisterInterface {
    // Capability registers
    #[register(offset = 0x0)]
    pub extcap_header: ReadOnlyRegister<u32>,
    #[register(offset = 0x4)]
    pub prot_cap_0: ReadWriteRegister<u32>,
    #[register(offset = 0x8)]
    pub prot_cap_1: ReadWriteRegister<u32>,
    #[register(offset = 0xc)]
    pub prot_cap_2: ReadWriteRegister<u32>,
    #[register(offset = 0x10)]
    pub prot_cap_3: ReadWriteRegister<u32>,

    // Device ID registers
    #[register(offset = 0x14)]
    pub device_id_0: ReadWriteRegister<u32>,
    #[register(offset = 0x18)]
    pub device_id_1: ReadWriteRegister<u32>,
    #[register(offset = 0x1c)]
    pub device_id_2: ReadWriteRegister<u32>,
    #[register(offset = 0x20)]
    pub device_id_3: ReadWriteRegister<u32>,
    #[register(offset = 0x24)]
    pub device_id_4: ReadWriteRegister<u32>,
    #[register(offset = 0x28)]
    pub device_id_5: ReadWriteRegister<u32>,
    #[register(offset = 0x2c)]
    pub device_id_6: ReadWriteRegister<u32>,

    // Status and control registers
    #[register(offset = 0x30)]
    pub device_status_0: ReadWriteRegister<u32>,
    #[register(offset = 0x34)]
    pub device_status_1: ReadWriteRegister<u32>,
    #[register(offset = 0x38)]
    pub device_reset: ReadWriteRegister<u32>,
    #[register(offset = 0x3c)]
    pub recovery_ctrl: ReadWriteRegister<u32>,
    #[register(offset = 0x40)]
    pub recovery_status: ReadWriteRegister<u32>,
    #[register(offset = 0x44)]
    pub hw_status: ReadWriteRegister<u32>,

    // Indirect FIFO registers
    #[register(offset = 0x48, write_fn = indirect_fifo_ctrl_0_write)]
    pub indirect_fifo_ctrl_0: ReadWriteRegister<u32, IndirectCtrl::Register>,
    #[register(offset = 0x4c, read_fn = indirect_fifo_ctrl_1_read)]
    pub indirect_fifo_ctrl_1: ReadWriteRegister<u32>,
    #[register(offset = 0x50)]
    pub indirect_fifo_status_0: ReadOnlyRegister<u32, IndirectStatus::Register>,
    #[register(offset = 0x54)]
    pub indirect_fifo_status_1: ReadOnlyRegister<u32>, // Write index
    #[register(offset = 0x58)]
    pub indirect_fifo_status_2: ReadOnlyRegister<u32>, // Read index
    #[register(offset = 0x5c)]
    pub indirect_fifo_status_3: ReadWriteRegister<u32>, // FIFO size
    #[register(offset = 0x60)]
    pub indirect_fifo_status_4: ReadWriteRegister<u32>, // Max transfer size
    #[register(offset = 0x64)]
    pub indirect_fifo_status_5: ReadWriteRegister<u32>,
    #[register(offset = 0x68, read_fn = indirect_fifo_data_read)]
    pub indirect_fifo_data: ReadWriteRegister<u32>,

    pub cms_data: Option<Rc<Vec<u8>>>, // TODO Multiple images?
}

impl RecoveryRegisterInterface {
    pub fn new() -> Self {
        Self {
            // Capability registers
            extcap_header: ReadOnlyRegister::new(0x0020C0), // CAP_LENGTH = 0x0020, CAP_ID = 0xC0
            prot_cap_0: ReadWriteRegister::new(0x2050_434f), // "OCP RECV" in ASCII
            prot_cap_1: ReadWriteRegister::new(0x5643_4552),
            // lower two bytes are version 1.1
            // required: device id = bit 0
            // required: device status = bit 4
            // recovery memory access / indirect ctrl = bit 5
            // c-image = bit 7
            // fifo cms support / indirect ctrl= bit 12
            prot_cap_2: ReadWriteRegister::new(0x10b1_0101),
            prot_cap_3: ReadWriteRegister::new(0x0000_0017), // maximum response time of 128ms, no heartbeat

            // Device ID registers
            device_id_0: ReadWriteRegister::new(0),
            device_id_1: ReadWriteRegister::new(0),
            device_id_2: ReadWriteRegister::new(0),
            device_id_3: ReadWriteRegister::new(0),
            device_id_4: ReadWriteRegister::new(0),
            device_id_5: ReadWriteRegister::new(0),
            device_id_6: ReadWriteRegister::new(0),

            // Status and control registers
            device_status_0: ReadWriteRegister::new(0),
            device_status_1: ReadWriteRegister::new(0),
            device_reset: ReadWriteRegister::new(0),
            recovery_ctrl: ReadWriteRegister::new(0),
            recovery_status: ReadWriteRegister::new(0),
            hw_status: ReadWriteRegister::new(0),

            // Indirect FIFO registers
            indirect_fifo_ctrl_0: ReadWriteRegister::new(0),
            indirect_fifo_ctrl_1: ReadWriteRegister::new(0),
            indirect_fifo_status_0: ReadOnlyRegister::new(0x1), // EMPTY=1
            indirect_fifo_status_1: ReadOnlyRegister::new(0),
            indirect_fifo_status_2: ReadOnlyRegister::new(0),
            indirect_fifo_status_3: ReadWriteRegister::new(0),
            indirect_fifo_status_4: ReadWriteRegister::new(0),
            indirect_fifo_status_5: ReadWriteRegister::new(0),
            indirect_fifo_data: ReadWriteRegister::new(0),

            cms_data: None,
        }
    }

    pub fn indirect_fifo_data_read(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?;
        }
        let image = match &self.cms_data {
            None => {
                println!("No image set in RRI");
                return Ok(0xffff_ffff);
            }
            Some(x) => x,
        };

        let cms = self.indirect_fifo_ctrl_0.reg.read(IndirectCtrl::CMS);
        if cms != 0 {
            println!("CMS {cms} not supported");
            return Ok(0xffff_ffff);
        }

        let read_index = self.indirect_fifo_status_2.reg.get();
        let address = read_index * 4;
        let image_len = image.len().try_into().unwrap();
        if address >= image_len {
            return Ok(0xffff_ffff);
        };
        if address >= image_len - 4 {
            self.indirect_fifo_status_0
                .reg
                .modify(IndirectStatus::FIFO_EMPTY::SET);
        }

        let address: usize = address.try_into().unwrap();
        let range = address..(address + 4);
        let data = &image[range];
        self.indirect_fifo_status_2.reg.set(read_index + 1);
        Ok(u32::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn indirect_fifo_ctrl_0_write(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }
        let load: ReadWriteRegister<u32, IndirectCtrl::Register> = ReadWriteRegister::new(val);
        if load.reg.is_set(IndirectCtrl::RESET) {
            if let Some(image) = &self.cms_data {
                let cms = load.reg.read(IndirectCtrl::CMS);
                if cms != 0 {
                    self.indirect_fifo_status_0
                        .reg
                        .set(IndirectStatus::REGION_TYPE::UnsupportedRegion.value);
                } else {
                    self.indirect_fifo_ctrl_1.reg.set(image.len() as u32 / 4); // DWORD
                    self.indirect_fifo_status_0
                        .reg
                        .set(IndirectStatus::REGION_TYPE::CodeSpaceRecovery.value);
                }
                self.indirect_fifo_status_1.reg.set(0);
                self.indirect_fifo_status_2.reg.set(0);
                self.indirect_fifo_status_0
                    .reg
                    .modify(IndirectStatus::FIFO_EMPTY::CLEAR + IndirectStatus::FIFO_FULL::CLEAR);
            } else {
                println!("No Image in RRI");
                self.indirect_fifo_status_0
                    .reg
                    .set(IndirectStatus::REGION_TYPE::UnsupportedRegion.value);
            }
        }
        Ok(())
    }

    pub fn indirect_fifo_ctrl_1_read(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            Err(BusError::LoadAccessFault)?
        }

        match &self.cms_data {
            Some(d) => Ok((d.as_ref().len() / mem::size_of::<u32>()) as u32),
            None => Ok(0),
        }
    }
}

impl Default for RecoveryRegisterInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;

    use super::*;

    const INDIRECT_FIFO_CTRL: RvAddr = 0x48;
    const INDIRECT_FIFO_RESET: RvData = 0x100;
    const INDIRECT_FIFO_IMAGE_SIZE: RvAddr = 0x4c;
    const INDIRECT_FIFO_STATUS: RvAddr = 0x50;
    const INDIRECT_FIFO_DATA: RvAddr = 0x68;

    #[test]
    fn test_get_image() {
        let image = Rc::new(vec![0xab; 512]);
        let image_len = image.len();
        let mut rri = RecoveryRegisterInterface::new();
        rri.cms_data = Some(image.clone());

        // Reset
        rri.write(RvSize::Word, INDIRECT_FIFO_CTRL, INDIRECT_FIFO_RESET)
            .unwrap();

        let image_size = rri.read(RvSize::Word, INDIRECT_FIFO_IMAGE_SIZE).unwrap();
        assert_eq!(image_len, image_size as usize * 4);

        let mut read_image = Vec::new();
        while rri.read(RvSize::Word, INDIRECT_FIFO_STATUS).unwrap() & 1 == 0 {
            let dword_read = rri.read(RvSize::Word, INDIRECT_FIFO_DATA).unwrap();
            let bytes = dword_read.to_le_bytes();
            read_image.extend_from_slice(&bytes);
        }
        assert_eq!(read_image, *image);
    }
}
