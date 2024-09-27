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
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;

// The description for these field and values come from https://www.opencompute.org/documents/ocp-recovery-document-1p0-final-1-pdf

const FIFO_SIZE_DWORD: usize = 64;

register_bitfields! [
    u8,

    /// Device ID type
    DidType [
        TYPE OFFSET(0) NUMBITS(8) [
            PCIVendor = 0,
            IANA = 1,
            UUID = 2,
            PnPVendor = 3,
            ACPIVendor = 4,
            IANAEnterprise = 5,
            NVMeMI = 0xff,
        ],
    ],
];

register_bitfields! [
    u32,

    /// Version and Capabilities
    VersionCapabilities [
        MAJOR OFFSET(0) NUMBITS(8) [],
        MINOR OFFSET(8) NUMBITS(8) [],
        IDENTIFICATION OFFSET(16) NUMBITS(1) [],
        FORCED_RECOVERY OFFSET(17) NUMBITS(1) [],
        MGMT_RESET OFFSET(18) NUMBITS(1) [],
        DEVICE_RESET OFFSET(19) NUMBITS(1) [],
        DEVICE_STATUS OFFSET(20) NUMBITS(1) [],
        RECOVERY_MEMORY_ACCESS OFFSET(21) NUMBITS(1) [],
        LOCAL_C_IMAGE_SUPPORT OFFSET(22) NUMBITS(1) [],
        PUSH_C_IMAGE_SUPPORT OFFSET(23) NUMBITS(1) [],
        INTERFACE_ISOLATION OFFSET(24) NUMBITS(1) [],
        HARDWARE_STATUS OFFSET(25) NUMBITS(1) [],
        VENDORS_COMMAND OFFSET(26) NUMBITS(1) [],
    ],

    /// Number of component memory spaces and timing magnitudes
    CmsTimings [
        CMS OFFSET(0) NUMBITS(8) [],
        MAX_RESPONSE_TIME OFFSET(8) NUMBITS(8) [],
        HEARTBEAT_PERIOD OFFSET(16) NUMBITS(8) [],
    ],

    /// Device Information
    DeviceInfo [
        STATUS OFFSET(0) NUMBITS(8) [
            StatusPending = 0,
            DeviceHealthy = 1,
            DeviceError = 2,
            RecoveryMode = 3,
            RecoveryPending = 4,
            RunningRecovery = 5,
            BootFailure = 0xe,
            FatalError = 0xf,
        ],
        ERROR OFFSET(8) NUMBITS(8) [
            NoProtocolError = 0,
            UnsupportedCmd = 1,
            UnsupportedParameter = 2,
            LengthWriteError = 3,
            CrcError = 4,
        ],
        RECOVERY_REASON OFFSET(16) NUMBITS(16) [
            NoBootFailureDetected = 0x0,
            GenericHardwareError = 0x1,
            GenericHardwareSoError = 0x2,
            SelfTestFailure = 0x3,
            CorruptedMissingCriticalData = 0x4,
            MissingCorruptKeyManifest = 0x5,
            AuthenticationFailureOnKeyManifest = 0x6,
            AntiRollbackFailureOnKeyManifest = 0x7,
            MissingCorruptBootLoaderFirmwareImage = 0x8,
            AuthenticationFailureOnBootLoaderFirmwareImage = 0x9,
            AntiRollbackFailureBootLoaderFirmwareImage = 0xA,
            MissingCorruptMainManagementFirmwareImage = 0xB,
            AuthenticationFailureMainManagementFirmwareImage = 0xC,
            AntiRollbackFailureMainManagementFirmwareImage = 0xD,
            MissingCorruptRecoveryFirmware = 0xE,
            AuthenticationFailureRecoveryFirmware = 0xF,
            AntiRollbackFailureOnRecoveryFirmware = 0x10,
            ForcedRecovery = 0x11,
            // 0x12 - 0x7F are reserved and not represented in the enum
            // 0x80 - 0xFF are assumed to be vendor unique codes and not represented in the enum
        ],
    ],

    /// Reset control
    ResetControl [
        DEVICE_RESET_CONTROL OFFSET(0) NUMBITS(8) [
            NoReset = 0,
            ResetDevice = 1,
            ResetManagement = 2,
            // All other numbers are reserved modes
        ],
        FORCED_RESET OFFSET(8) NUMBITS(8) [
            NoForcedRecovery = 0,
            // 1 - 0xe Reserved
            RecoveryMode = 0xf,
            // Rest is reserved
        ],
        INTERFACE_CONTROL OFFSET(16) NUMBITS(1) [],
    ],

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
    //    #[register_array(offset = 0x00)]
    //    prot_cap_magic: [u8; 8],
    #[register(offset = 0x08)]
    prot_cap_version: ReadOnlyRegister<u32, VersionCapabilities::Register>,

    #[register(offset = 0x0c)]
    prot_cap_cms_timing: ReadOnlyRegister<u32, CmsTimings::Register>,

    // TODO will this work with 32bit memory access?
    //    #[register(offset = 0x10)]
    //    device_id_descriptor_type: ReadOnlyRegister<u8, DidType::Register>,

    //    #[register(offset = 0x11)]
    //    device_id_vendor_id_string_length: ReadOnlyRegister<u8>,

    //    #[register_array(offset = 0x12)]
    //    device_id: [u8; 22],
    #[register(offset = 0x28)]
    device_info: ReadOnlyRegister<u32, DeviceInfo::Register>,

    //    #[register(offset = 0x2c)]
    //    hearthbeat: ReadOnlyRegister<u16>, // TODO do we need hearthbeat?

    //    #[register(offset = 0x2e)]
    //    vendor_status_length: ReadOnlyRegister<u8>, // TODO Not supported?
    #[register(offset = 0x30)]
    device_reset: ReadWriteRegister<u32, ResetControl::Register>,

    #[register(offset = 0x34)]
    recovery_control: ReadWriteRegister<u32, RecoveryControl::Register>,

    #[register(offset = 0x38)]
    recovery_status: ReadOnlyRegister<u32, RecoveryStatus::Register>,

    #[register(offset = 0x3c)]
    hw_status: ReadOnlyRegister<u32, HwStatus::Register>,

    #[register(offset = 0x40, write_fn = indirect_fifo_ctrl_write)]
    indirect_fifo_ctrl: ReadWriteRegister<u32, IndirectCtrl::Register>,

    #[register(offset = 0x44)] // TODO Aligned here but spec says otherwise?
    indirect_fifo_image_size: ReadOnlyRegister<u32>,

    #[register(offset = 0x48)]
    indirect_fifo_status: ReadOnlyRegister<u32, IndirectStatus::Register>,

    #[register(offset = 0x4c)]
    write_index: ReadOnlyRegister<u32>,

    #[register(offset = 0x50)]
    read_index: ReadOnlyRegister<u32>,

    #[register(offset = 0x54)]
    indirect_size: ReadOnlyRegister<u32>,

    #[register(offset = 0x58)]
    max_transfer_window: ReadOnlyRegister<u32>,

    // TODO email said it's 24 sized
    #[register(offset = 0x6c, read_fn = indirect_fifo_data_read)]
    indirect_fifo_data: ReadOnlyRegister<u32>,
    //    indirect_fifo_data: ReadWriteRegisterArray<u32, FIFO_SIZE_DWORD>, // TODO should be larger size but for FW with only read use just one dword
    pub cms_data: Rc<Vec<u8>>, // TODO Multiple images?
}

impl RecoveryRegisterInterface {
    //    const MAGIC: [u8; 8] = [0x4f, 0x43, 0x50, 0x20, 0x52, 0x45, 0x43, 0x56];
    const MAJOR_VERSION: u32 = 0x01;
    const MINOR_VERSION: u32 = 0x00;

    pub fn new(cms_data: Rc<Vec<u8>>) -> Self {
        Self {
            //            prot_cap_magic: Self::MAGIC,
            prot_cap_version: ReadOnlyRegister::new(
                VersionCapabilities::MAJOR.val(Self::MAJOR_VERSION).value
                    | VersionCapabilities::MINOR.val(Self::MINOR_VERSION).value,
            ),
            prot_cap_cms_timing: ReadOnlyRegister::new(
                CmsTimings::CMS.val(1).value // TODO
                    | CmsTimings::MAX_RESPONSE_TIME.val(0xff).value // TODO
                    | CmsTimings::HEARTBEAT_PERIOD.val(0).value, // TODO 0 means unsupported
            ),
            // device_id_descriptor_type: ReadOnlyRegister::new(DidType::TYPE::UUID.value), // TODO
            // device_id_vendor_id_string_length: ReadOnlyRegister::new(0), // not supported
            // device_id: [0; 22],
            device_info: ReadOnlyRegister::new(
                DeviceInfo::STATUS::DeviceHealthy.value
                    | DeviceInfo::ERROR::NoProtocolError.value
                    | DeviceInfo::RECOVERY_REASON::NoBootFailureDetected.value,
            ),
            // hearthbeat: ReadOnlyRegister::new(0),
            // vendor_status_length: ReadOnlyRegister::new(0),
            device_reset: ReadWriteRegister::new(0),
            recovery_control: ReadWriteRegister::new(0),
            recovery_status: ReadOnlyRegister::new(0),
            hw_status: ReadOnlyRegister::new(0), // TODO
            indirect_fifo_ctrl: ReadWriteRegister::new(0),
            indirect_fifo_image_size: ReadOnlyRegister::new(0),
            indirect_fifo_status: ReadOnlyRegister::new(0),
            write_index: ReadOnlyRegister::new(0),
            read_index: ReadOnlyRegister::new(0),
            indirect_size: ReadOnlyRegister::new(FIFO_SIZE_DWORD.try_into().unwrap()),
            max_transfer_window: ReadOnlyRegister::new(0),
            indirect_fifo_data: ReadOnlyRegister::new(0),
            cms_data,
        }
    }

    pub fn indirect_fifo_data_read(&mut self, size: RvSize) -> Result<RvData, BusError> {
        if size != RvSize::Word {
            return Err(BusError::LoadAccessFault);
        }
        let cms = self.indirect_fifo_ctrl.reg.read(IndirectCtrl::CMS);
        if cms != 0 {
            println!("CMS {cms} not supported");
            return Ok(0xffff_ffff);
        }

        let read_index = self.read_index.reg.get();
        let address = read_index * 4;
        let image_len: u32 = self.cms_data.len().try_into().unwrap();
        if address >= image_len {
            return Ok(0xffff_ffff);
        };
        if address >= image_len - 4 {
            self.indirect_fifo_status
                .reg
                .modify(IndirectStatus::FIFO_EMPTY::SET);
        }

        let address: usize = address.try_into().unwrap();
        let range = address..(address + 4);
        let data = &self.cms_data[range];
        self.read_index.reg.set(read_index + 1);
        Ok(u32::from_le_bytes(data.try_into().unwrap()))
    }

    pub fn indirect_fifo_ctrl_write(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }
        let load: ReadWriteRegister<u32, IndirectCtrl::Register> = ReadWriteRegister::new(val);
        if load.reg.is_set(IndirectCtrl::RESET) {
            let cms = load.reg.read(IndirectCtrl::CMS);
            if cms != 0 {
                self.indirect_fifo_status
                    .reg
                    .set(IndirectStatus::REGION_TYPE::UnsupportedRegion.value);
            } else {
                self.indirect_fifo_image_size
                    .reg
                    .set(self.cms_data.len().try_into().unwrap());
                self.indirect_fifo_status
                    .reg
                    .set(IndirectStatus::REGION_TYPE::CodeSpaceRecovery.value);
            }
            self.write_index.reg.set(0);
            self.read_index.reg.set(0);
            self.indirect_fifo_status
                .reg
                .modify(IndirectStatus::FIFO_EMPTY::CLEAR + IndirectStatus::FIFO_FULL::CLEAR);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvAddr;

    use super::*;

    const INDIRECT_FIFO_CTRL: RvAddr = 0x40;
    const INDIRECT_FIFO_RESET: RvData = 0x100;
    const INDIRECT_FIFO_IMAGE_SIZE: RvAddr = 0x44;
    const INDIRECT_FIFO_STATUS: RvAddr = 0x48;
    const INDIRECT_FIFO_DATA: RvAddr = 0x6c;

    #[test]
    fn test_get_image() {
        let image = Rc::new(vec![0xab; 512]);
        let image_len = image.len();
        let mut rri = RecoveryRegisterInterface::new(image.clone());

        // Reset
        rri.write(RvSize::Word, INDIRECT_FIFO_CTRL, INDIRECT_FIFO_RESET)
            .unwrap();

        let image_size = rri.read(RvSize::Word, INDIRECT_FIFO_IMAGE_SIZE).unwrap();
        assert_eq!(image_len, image_size.try_into().unwrap());

        let mut read_image = Vec::new();
        while rri.read(RvSize::Word, INDIRECT_FIFO_STATUS).unwrap() & 1 == 0 {
            let dword_read = rri.read(RvSize::Word, INDIRECT_FIFO_DATA).unwrap();
            let bytes = dword_read.to_le_bytes();
            read_image.extend_from_slice(&bytes);
        }
        assert_eq!(read_image, *image);
    }
}
