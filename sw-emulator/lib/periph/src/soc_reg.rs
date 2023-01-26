/*++

Licensed under the Apache-2.0 license.

File Name:

    soc_reg.rs

Abstract:

    File contains SOC Register implementation

--*/

use caliptra_emu_bus::BusError::{LoadAccessFault, StoreAccessFault};
use caliptra_emu_bus::{Bus, BusError, ReadOnlyMemory, ReadOnlyRegister, ReadWriteRegister};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::Readable;
use tock_registers::register_bitfields;

/// Unique device secret size
const UDS_SIZE: usize = 48;

/// Field entropy size
const FIELD_ENTROPY_SIZE: usize = 128;

/// Deobfuscation engine key size
const DOE_KEY_SIZE: usize = 32;

/// Key manigest private key hash size
const KEY_MANIFEST_PK_HASH_SIZE: usize = 48;

/// Owner key manigest private key hash size
const OWNER_KEY_MANIFEST_PK_HASH_SIZE: usize = 48;

/// Runtime SVN size
const RUNTIME_SVN_SIZE: usize = 16;

/// Idevid certificate attribute size
const IDEVID_CERT_ATTR_SIZE: usize = 96;

/// Idevid manufacturer hsm id size
const IDEVID_MANUF_HSM_ID_SIZE: usize = 16;

register_bitfields! [
    u32,

    /// Flow Status
    FlowStatus [
        STATUS OFFSET(0) NUMBITS(28) [],
        READY_FOR_FW OFFSET(28) NUMBITS(1) [],
        READY_FOR_RT OFFSET(29) NUMBITS(1) [],
        READY_FOR_FUSES OFFSET(30) NUMBITS(1) [],
        MBOX_FLOW_DONE OFFSET(31) NUMBITS(1) [],
   ],

   /// Security State
   SecurityState [
       LIFE_CYCLE OFFSET(0) NUMBITS(2) [
           UNPROVISIONED = 0b00,
           MANUFACTURING = 0b01,
           PRODUCTION = 011,
       ],
       DEBUG_LOCKED OFFSET(2) NUMBITS(1) [],
   ],

    /// Valid User Lock
    ValiPAUserLock [
        LOCK OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
   ],

    /// User Lock TRNG
    TrngPauserLock [
            LOCK OFFSET(0) NUMBITS(1) [],
            RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// TRNG Done
    TrngDone [
        DONE OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Fuse Write Done
    FuseWriteDone [
        DONE OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Boot FSM Go
    BootFsmGo [
        GO OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Clock Gating Enable
    ClockGatingEnable [
        EN OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Key Manifest Private Key Hash Mask
    KeyManifestPkHashMask [
        MASK OFFSET(0) NUMBITS(4) [],
        RSVD OFFSET(4) NUMBITS(28) [],
    ],

    /// Owner Key Manifest Private Key Hash Mask
    OwnerKeyManifestPkHashMask [
        MASK OFFSET(0) NUMBITS(4) [],
        RSVD OFFSET(4) NUMBITS(28) [],
    ],

    /// Anti Rollback Disable
    AntiRollbackDisable [
        DIS OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// ICCM Lock
    IccmLock [
        LOCK OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Firmware Update Reset
    FwUpdateReset [
        CORE_RST OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Firmware Update Reset Wait Cycles
    FwUpdateResetWaitCycles [
        WAIT_CYCLES OFFSET(0) NUMBITS(8) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],
];

/// SOC Register peripheral
#[derive(Clone)]
pub struct SocRegisters {
    regs: Rc<RefCell<SocRegistersImpl>>,
}

impl SocRegisters {
    /// Caliptra Register Start Address
    const CALIPTRA_REG_START_ADDR: u32 = 0x00;
    /// Caliptra Register End Address
    const CALIPTRA_REG_END_ADDR: u32 = 0x62C;

    /// Create an instance of SOC register peripheral
    pub fn new() -> Self {
        Self {
            regs: Rc::new(RefCell::new(SocRegistersImpl::new())),
        }
    }

    /// Get Unique device secret
    pub fn uds(&self) -> [u8; UDS_SIZE] {
        self.regs.borrow().uds.data().clone()
    }

    // Get field entropy
    pub fn field_entropy(&self) -> [u8; FIELD_ENTROPY_SIZE] {
        self.regs.borrow().field_entropy.data().clone()
    }

    /// Get deobfuscation engine key
    pub fn doe_key(&self) -> [u8; DOE_KEY_SIZE] {
        self.regs.borrow().doe_key.data().clone()
    }

    pub fn key_manifest_pk_hash(&self) -> [u8; KEY_MANIFEST_PK_HASH_SIZE] {
        self.regs.borrow().key_manifest_pk_hash.data().clone()
    }

    pub fn owner_key_manifest_pk_hash(&self) -> [u8; OWNER_KEY_MANIFEST_PK_HASH_SIZE] {
        self.regs.borrow().owner_key_manifest_pk_hash.data().clone()
    }

    pub fn key_manifest_svn(&self) -> u32 {
        self.regs.borrow().key_manifest_svn.reg.get()
    }

    pub fn boot_loader_svn(&self) -> u32 {
        self.regs.borrow().boot_loader_svn.reg.get()
    }

    pub fn runtime_svn(&self) -> [u8; RUNTIME_SVN_SIZE] {
        self.regs.borrow().runtime_svn.data().clone()
    }

    pub fn anti_rollback_disable(&self) -> u32 {
        self.regs.borrow().anti_rollback_disable.reg.get()
    }

    pub fn idevid_cert_attr(&self) -> [u8; IDEVID_CERT_ATTR_SIZE] {
        self.regs.borrow().idevid_cert_attr.data().clone()
    }

    pub fn idevid_manuf_hsm_id(&self) -> [u8; IDEVID_MANUF_HSM_ID_SIZE] {
        self.regs.borrow().idevid_manuf_hsm_id.data().clone()
    }

    pub fn iccm_lock(&self) -> u32 {
        self.regs.borrow().iccm_lock.reg.get()
    }

    pub fn fw_update_reset(&self) -> u32 {
        self.regs.borrow().fw_update_reset.reg.get()
    }

    pub fn fw_update_reset_wait_cycles(&self) -> u32 {
        self.regs.borrow().fw_update_reset_wait_cycles.reg.get()
    }

    pub fn nmi_vector(&self) -> u32 {
        self.regs.borrow().nmi_vector.reg.get()
    }

    /// Clear secrets
    pub fn clear_secrets(&mut self) {
        self.regs.borrow_mut().clear_secrets();
    }
}

impl Bus for SocRegisters {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            Self::CALIPTRA_REG_START_ADDR..=Self::CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().read(size, addr)
            }
            _ => Err(LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            Self::CALIPTRA_REG_START_ADDR..=Self::CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().write(size, addr, val)
            }
            _ => Err(StoreAccessFault),
        }
    }
}

/// SOC Register implementation
#[derive(Bus)]
struct SocRegistersImpl {
    /// Hardware Error Fatal
    #[register(offset = 0x0000_0000)]
    hw_err_fatal: ReadWriteRegister<u32>,

    /// Hardware Error Non Fatal
    #[register(offset = 0x0000_0004)]
    hw_err_non_fatal: ReadWriteRegister<u32>,

    /// Firmware Error Fatal
    #[register(offset = 0x0000_0008)]
    fw_err_fatal: ReadWriteRegister<u32>,

    /// Firmware Error Non Fatal
    #[register(offset = 0x0000_000C)]
    fw_err_non_fatal: ReadWriteRegister<u32>,

    /// Hardware Error Encoding
    #[register(offset = 0x0000_0010)]
    hw_err_enc: ReadWriteRegister<u32>,

    /// Firmware Error Encoding
    #[register(offset = 0x0000_0014)]
    fw_err_enc: ReadWriteRegister<u32>,

    /// Boot Status
    #[register(offset = 0x0000_0018)]
    boot_status: ReadWriteRegister<u32>,

    /// Flow Status
    #[register(offset = 0x0000_001C)]
    flow_status: ReadWriteRegister<u32, FlowStatus::Register>,

    /// Reset Reason
    #[register(offset = 0x0000_0020)]
    reset_reason: ReadOnlyRegister<u32>,

    /// Security State
    #[register(offset = 0x0000_0024)]
    security_state: ReadOnlyRegister<u32, SecurityState::Register>,

    /// Fuse Write Done
    #[register(offset = 0x0000_008c)]
    fuse_write_done: ReadWriteRegister<u32, FuseWriteDone::Register>,

    /// Timer Config
    #[register(offset = 0x0000_0090)]
    timer_cfg: ReadOnlyRegister<u32>,

    /// Boot FSM Go
    #[register(offset = 0x0000_0094)]
    boot_fsm_go: ReadWriteRegister<u32, BootFsmGo::Register>,

    /// Clock Gating Enable
    #[register(offset = 0x0000_0098)]
    clk_gating_enable: ReadWriteRegister<u32, ClockGatingEnable::Register>,

    /// [TODO] Generic Input Wires
    /// [TODO] Generic Output Wires

    /// Unique device secret
    uds: ReadOnlyMemory<UDS_SIZE>,

    /// Field entropy
    field_entropy: ReadOnlyMemory<FIELD_ENTROPY_SIZE>,

    /// Key Manifest Private
    #[peripheral(offset = 0x0000_0250, mask = 0x0000_003F)]
    key_manifest_pk_hash: ReadOnlyMemory<KEY_MANIFEST_PK_HASH_SIZE>,

    /// Key Manifest Private Key Hash Mask
    #[register(offset = 0x0000_0280)]
    key_manifest_pk_hash_mask: ReadOnlyRegister<u32, KeyManifestPkHashMask::Register>,

    /// Owner Key Manifest Private Key Hash
    #[peripheral(offset = 0x0000_0284, mask = 0x0000_003F)]
    owner_key_manifest_pk_hash: ReadOnlyMemory<OWNER_KEY_MANIFEST_PK_HASH_SIZE>,

    /// Owner Key Manifest Private Key Hash Mask
    #[register(offset = 0x0000_02b4)]
    owner_key_manifest_pk_hash_mask: ReadOnlyRegister<u32, OwnerKeyManifestPkHashMask::Register>,

    /// Key Manifest SVN
    #[register(offset = 0x0000_02b8)]
    key_manifest_svn: ReadOnlyRegister<u32>,

    /// Boot Loader SVN
    #[register(offset = 0x0000_02bc)]
    boot_loader_svn: ReadOnlyRegister<u32>,

    /// Runtime SVN
    #[peripheral(offset = 0x0000_02c0, mask = 0x0000_000F)]
    runtime_svn: ReadOnlyMemory<RUNTIME_SVN_SIZE>,

    /// Anti-Rollback Disable
    #[register(offset = 0x0000_02d0)]
    anti_rollback_disable: ReadOnlyRegister<u32, AntiRollbackDisable::Register>,

    /// idevid Cert Attribute
    #[peripheral(offset = 0x0000_02d4, mask = 0x0000_007F)]
    idevid_cert_attr: ReadOnlyMemory<IDEVID_CERT_ATTR_SIZE>,

    /// idevid manufacturer HSM id
    #[peripheral(offset = 0x0000_0334, mask = 0x0000_000F)]
    idevid_manuf_hsm_id: ReadOnlyMemory<IDEVID_MANUF_HSM_ID_SIZE>,

    /// Deobfuscation engine key
    doe_key: ReadOnlyMemory<DOE_KEY_SIZE>,

    /// ICCM lock
    #[register(offset = 0x0000_0620)]
    iccm_lock: ReadWriteRegister<u32, IccmLock::Register>,

    /// Firmware update reset
    #[register(offset = 0x0000_0624)]
    fw_update_reset: ReadWriteRegister<u32, FwUpdateReset::Register>,

    /// Firmware update reset wait cycles
    #[register(offset = 0x0000_0628)]
    fw_update_reset_wait_cycles: ReadWriteRegister<u32, FwUpdateResetWaitCycles::Register>,

    /// NMI Vector
    #[register(offset = 0x0000_062c)]
    nmi_vector: ReadWriteRegister<u32>,
}

impl SocRegistersImpl {
    /// Clock period for 450 MHz Clock in pico seconds
    const CLOCK_PERIOD: u32 = 2222000;

    /// Wait cycles period for firmware update reset.
    const RESET_WAIT_CYCLES: u8 = 5;

    /// Default Deobfuscation engine key
    const DOE_KEY: [u8; DOE_KEY_SIZE] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x7, 0x3B, 0x61, 0x8, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x9, 0x14,
        0xDF, 0xF4,
    ];

    /// Default unique device secret
    const UDS: [u8; UDS_SIZE] = [
        0xF5, 0x8C, 0x4C, 0x4, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB,
        0xD6, 0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70,
        0x2C, 0x7D, 0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x4,
        0x23, 0x14, 0x61,
    ];

    /// Create an instance of SOC register implementation
    pub fn new() -> Self {
        let mut regs = Self {
            uds: ReadOnlyMemory::new(),
            field_entropy: ReadOnlyMemory::new(),
            doe_key: ReadOnlyMemory::new(),
            hw_err_fatal: ReadWriteRegister::new(0),
            hw_err_non_fatal: ReadWriteRegister::new(0),
            fw_err_fatal: ReadWriteRegister::new(0),
            fw_err_non_fatal: ReadWriteRegister::new(0),
            hw_err_enc: ReadWriteRegister::new(0),
            fw_err_enc: ReadWriteRegister::new(0),
            boot_status: ReadWriteRegister::new(0),
            flow_status: ReadWriteRegister::new(0),
            reset_reason: ReadOnlyRegister::new(0),
            security_state: ReadOnlyRegister::new(
                (SecurityState::DEBUG_LOCKED::CLEAR + SecurityState::LIFE_CYCLE::UNPROVISIONED)
                    .value,
            ),
            timer_cfg: ReadOnlyRegister::new(Self::CLOCK_PERIOD),
            fuse_write_done: ReadWriteRegister::new((FuseWriteDone::DONE::CLEAR).value),
            boot_fsm_go: ReadWriteRegister::new((BootFsmGo::GO::CLEAR).value),
            clk_gating_enable: ReadWriteRegister::new((ClockGatingEnable::EN::CLEAR).value),
            key_manifest_pk_hash: ReadOnlyMemory::new(),
            key_manifest_pk_hash_mask: ReadOnlyRegister::new(
                (KeyManifestPkHashMask::MASK::CLEAR).value,
            ),
            owner_key_manifest_pk_hash: ReadOnlyMemory::new(),
            owner_key_manifest_pk_hash_mask: ReadOnlyRegister::new(
                (OwnerKeyManifestPkHashMask::MASK::CLEAR).value,
            ),
            key_manifest_svn: ReadOnlyRegister::new(0),
            boot_loader_svn: ReadOnlyRegister::new(0),
            runtime_svn: ReadOnlyMemory::new(),
            anti_rollback_disable: ReadOnlyRegister::new((AntiRollbackDisable::DIS::CLEAR).value),
            idevid_cert_attr: ReadOnlyMemory::new(),
            idevid_manuf_hsm_id: ReadOnlyMemory::new(),
            iccm_lock: ReadWriteRegister::new((IccmLock::LOCK::CLEAR).value),
            fw_update_reset: ReadWriteRegister::new((FwUpdateReset::CORE_RST::CLEAR).value),
            fw_update_reset_wait_cycles: ReadWriteRegister::new(
                (FwUpdateResetWaitCycles::WAIT_CYCLES.val(Self::RESET_WAIT_CYCLES as u32)).value,
            ),
            nmi_vector: ReadWriteRegister::new(0),
        };

        regs.uds.data_mut().copy_from_slice(&Self::UDS);
        regs.doe_key.data_mut().copy_from_slice(&Self::DOE_KEY);
        regs.field_entropy.data_mut().fill(0xFF);
        regs
    }

    /// Clear secrets
    pub fn clear_secrets(&mut self) {
        self.uds.data_mut().fill(0);
        self.field_entropy.data_mut().fill(0);
        self.doe_key.data_mut().fill(0);
    }
}

#[cfg(test)]
mod tests {
    use caliptra_emu_bus::{Bus, BusError};
    use caliptra_emu_types::{RvAddr, RvSize};

    use crate::SocRegisters;

    use super::*;

    const HW_ERR_FATAL_REG_OFFSET: RvAddr = 0x0;
    const HW_ERR_NON_FATAL_REG_OFFSET: RvAddr = 0x4;
    const FW_ERR_FATAL_REG_OFFSET: RvAddr = 0x8;
    const FW_ERR_NON_FATAL_REG_OFFSET: RvAddr = 0xc;
    const HW_ERR_ENC_REG_OFFSET: RvAddr = 0x10;
    const FW_ERR_ENC_REG_OFFSET: RvAddr = 0x14;
    const BOOT_STATUS_REG_OFFSET: RvAddr = 0x18;
    const FLOW_STATUS_REG_OFFSET: RvAddr = 0x1c;
    const RESET_REASON_REG_OFFSET: RvAddr = 0x20;
    const SECURITY_STATE_REG_OFFSET: RvAddr = 0x24;
    const PAUSER_LOCK_REG_START_OFFSET: RvAddr = 0x3c;
    const TRNG_DATA_REG_START_OFFSET: RvAddr = 0x58;
    const FUSE_WRITE_DONE_REG_OFFSET: RvAddr = 0x8c;
    const TIMER_CFG_REG_OFFSET: RvAddr = 0x90;
    const CLOCK_PERIOD: u32 = 2222000;
    const BOOT_FSM_GO_REG_OFFSET: RvAddr = 0x94;
    const CLK_GATING_ENABLE_REG_OFFSET: RvAddr = 0x98;
    const KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET: RvAddr = 0x280;
    const OWNER_KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET: RvAddr = 0x2b4;
    const KEY_MANIFEST_SVN_REG_OFFSET: RvAddr = 0x2b8;
    const BOOT_LOADER_SVN_REG_OFFSET: RvAddr = 0x2bc;
    const ANTI_ROLLBACK_DISABLE_REG_OFFSET: RvAddr = 0x2d0;
    const IDEVID_CERT_ATTR_START_OFFSET: RvAddr = 0x2d4;
    const IDEVID_MANUF_HSM_ID_START_OFFSET: RvAddr = 0x334;
    const ICCM_LOCK_REG_OFFSET: RvAddr = 0x620;
    const FW_UPDATE_RESET_REG_OFFSET: RvAddr = 0x624;
    const FW_UPDATE_RESET_WAIT_CYCLES_REG_OFFSET: RvAddr = 0x628;
    const NMI_VECTOR_REG_OFFSET: RvAddr = 0x62c;

    #[test]
    fn test_read_write_hw_err_fatal_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, HW_ERR_FATAL_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, HW_ERR_FATAL_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_hw_err_non_fatal_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, HW_ERR_NON_FATAL_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, HW_ERR_NON_FATAL_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_fw_err_fatal_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, FW_ERR_FATAL_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FW_ERR_FATAL_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_fw_err_non_fatal_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, FW_ERR_NON_FATAL_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FW_ERR_NON_FATAL_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_hw_err_enc_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, HW_ERR_ENC_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, HW_ERR_ENC_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_fw_err_enc_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, FW_ERR_ENC_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FW_ERR_ENC_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_boot_status_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, BOOT_STATUS_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, BOOT_STATUS_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_flow_status_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, FLOW_STATUS_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FLOW_STATUS_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_reset_reason_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, RESET_REASON_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, RESET_REASON_REG_OFFSET).ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_security_state_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, SECURITY_STATE_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, SECURITY_STATE_REG_OFFSET).ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_pauser_lock_regs() {
        let mut soc_reg = SocRegisters::new();

        for idx in 0u32..5 {
            assert_eq!(
                soc_reg
                    .write(
                        RvSize::Word,
                        PAUSER_LOCK_REG_START_OFFSET + (idx << 2),
                        0xDEADBEEF
                    )
                    .ok(),
                None
            );

            assert_eq!(
                soc_reg
                    .read(RvSize::Word, PAUSER_LOCK_REG_START_OFFSET + (idx << 2))
                    .ok(),
                None
            );
        }
    }

    #[test]
    fn test_read_write_trng_data_regs() {
        let mut soc_reg = SocRegisters::new();

        for idx in 0u32..12 {
            assert_eq!(
                soc_reg
                    .write(
                        RvSize::Word,
                        TRNG_DATA_REG_START_OFFSET + (idx << 2),
                        0xDEADBEEF
                    )
                    .ok(),
                None
            );

            assert_eq!(
                soc_reg
                    .read(RvSize::Word, TRNG_DATA_REG_START_OFFSET + (idx << 2))
                    .ok(),
                None
            );
        }
    }

    #[test]
    fn test_read_write_fuse_write_done_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, FUSE_WRITE_DONE_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FUSE_WRITE_DONE_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_timer_cfg_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, TIMER_CFG_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, TIMER_CFG_REG_OFFSET).ok(),
            Some(CLOCK_PERIOD)
        );
    }

    #[test]
    fn test_read_write_boot_fsm_go_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, BOOT_FSM_GO_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, BOOT_FSM_GO_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_clk_gating_enable_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, CLK_GATING_ENABLE_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg
                .read(RvSize::Word, CLK_GATING_ENABLE_REG_OFFSET)
                .ok(),
            Some(0xDEADBEEF)
        );
    }

    #[test]
    fn test_read_write_key_manifest_pk_hash_mask_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(
                    RvSize::Word,
                    KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET,
                    0xDEADBEEF
                )
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg
                .read(RvSize::Word, KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET)
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_owner_key_manifest_pk_hash_mask_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(
                    RvSize::Word,
                    OWNER_KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET,
                    0xDEADBEEF
                )
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg
                .read(RvSize::Word, OWNER_KEY_MANIFEST_PK_HASH_MASK_REG_OFFSET)
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_owner_key_manifest_svn_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, KEY_MANIFEST_SVN_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, KEY_MANIFEST_SVN_REG_OFFSET).ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_boot_loader_svn_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, BOOT_LOADER_SVN_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, BOOT_LOADER_SVN_REG_OFFSET).ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_anti_rollback_disable_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, ANTI_ROLLBACK_DISABLE_REG_OFFSET, 0xDEADBEEF)
                .err(),
            Some(BusError::StoreAccessFault)
        );

        assert_eq!(
            soc_reg
                .read(RvSize::Word, ANTI_ROLLBACK_DISABLE_REG_OFFSET)
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn test_read_write_idevid_cert_attr() {
        let mut soc_reg = SocRegisters::new();

        for idx in 0u32..((IDEVID_CERT_ATTR_SIZE / 4) as u32) {
            assert_eq!(
                soc_reg
                    .write(
                        RvSize::Word,
                        IDEVID_CERT_ATTR_START_OFFSET + (idx << 2),
                        0xDEADBEEF
                    )
                    .err(),
                Some(BusError::StoreAccessFault)
            );

            assert_eq!(
                soc_reg
                    .read(RvSize::Word, IDEVID_CERT_ATTR_START_OFFSET + (idx << 2))
                    .ok(),
                None
            );
        }
    }

    #[test]
    fn test_read_write_idevid_manuf_hsm_id() {
        let mut soc_reg = SocRegisters::new();

        for idx in 0u32..((IDEVID_MANUF_HSM_ID_SIZE / 4) as u32) {
            assert_eq!(
                soc_reg
                    .write(
                        RvSize::Word,
                        IDEVID_MANUF_HSM_ID_START_OFFSET + (idx << 2),
                        0xDEADBEEF
                    )
                    .err(),
                Some(BusError::StoreAccessFault)
            );

            assert_eq!(
                soc_reg
                    .read(RvSize::Word, IDEVID_MANUF_HSM_ID_START_OFFSET + (idx << 2))
                    .ok(),
                None
            );
        }
    }

    #[test]
    fn test_read_write_iccm_lock_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(
                    RvSize::Word,
                    ICCM_LOCK_REG_OFFSET,
                    IccmLock::LOCK.val(1).value
                )
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, ICCM_LOCK_REG_OFFSET).ok(),
            Some(IccmLock::LOCK.val(1).value)
        );
    }

    #[test]
    fn test_read_write_fw_update_reset_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(
                    RvSize::Word,
                    FW_UPDATE_RESET_REG_OFFSET,
                    FwUpdateReset::CORE_RST.val(1).value
                )
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, FW_UPDATE_RESET_REG_OFFSET).ok(),
            Some(FwUpdateReset::CORE_RST.val(1).value)
        );
    }

    #[test]
    fn test_read_write_fw_update_reset_wait_cycles_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(
                    RvSize::Word,
                    FW_UPDATE_RESET_WAIT_CYCLES_REG_OFFSET,
                    FwUpdateResetWaitCycles::WAIT_CYCLES.val(2).value
                )
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg
                .read(RvSize::Word, FW_UPDATE_RESET_WAIT_CYCLES_REG_OFFSET)
                .ok(),
            Some(FwUpdateResetWaitCycles::WAIT_CYCLES.val(2).value)
        );
    }

    #[test]
    fn test_read_write_nmi_vector_reg() {
        let mut soc_reg = SocRegisters::new();
        assert_eq!(
            soc_reg
                .write(RvSize::Word, NMI_VECTOR_REG_OFFSET, 0xDEADBEEF)
                .ok(),
            Some(())
        );

        assert_eq!(
            soc_reg.read(RvSize::Word, NMI_VECTOR_REG_OFFSET).ok(),
            Some(0xDEADBEEF)
        );
    }
}
