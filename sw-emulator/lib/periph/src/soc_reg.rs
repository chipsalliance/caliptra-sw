/*++

Licensed under the Apache-2.0 license.

File Name:

    soc_reg.rs

Abstract:

    File contains SOC Register implementation

--*/

use crate::{CaliptraRootBusArgs, Iccm, Mailbox};
use caliptra_emu_bus::BusError::{LoadAccessFault, StoreAccessFault};
use caliptra_emu_bus::{
    Bus, BusError, Clock, ReadOnlyMemory, ReadOnlyRegister, ReadWriteMemory, ReadWriteRegister,
    Register, Timer, TimerAction,
};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

type ReadyForFwCallback = Box<dyn FnMut(&mut Mailbox)>;

/// CPTRA_HW_ERROR_FATAL Register Start Address
const CPTRA_HW_ERROR_FATAL_START: u32 = 0x0;

/// CPTRA_HW_ERROR_FATAL Register End Address
const CPTRA_HW_ERROR_FATAL_END: u32 = 0x3;

/// CPTRA_HW_ERROR_NON_FATAL Register Start Address
const CPTRA_HW_ERROR_NON_FATAL_START: u32 = 0x4;

/// CPTRA_HW_ERROR_NON_FATAL Register End Address
const CPTRA_HW_ERROR_NON_FATAL_END: u32 = 0x7;

/// CPTRA_FW_ERROR_FATAL Register Start Address
const CPTRA_FW_ERROR_FATAL_START: u32 = 0x8;

/// CPTRA_FW_ERROR_FATAL Register End Address
const CPTRA_FW_ERROR_FATAL_END: u32 = 0xb;

/// CPTRA_FW_ERROR_NON_FATAL Register Start Address
const CPTRA_FW_ERROR_NON_FATAL_START: u32 = 0xc;

/// CPTRA_FW_ERROR_NON_FATAL Register End Address
const CPTRA_FW_ERROR_NON_FATAL_END: u32 = 0xf;

/// CPTRA_HW_ERROR_ENC Register Start Address
const CPTRA_HW_ERROR_ENC_START: u32 = 0x10;

/// CPTRA_HW_ERROR_ENC Register End Address
const CPTRA_HW_ERROR_ENC_END: u32 = 0x13;

/// CPTRA_FW_ERROR_ENC Register Start Address
const CPTRA_FW_ERROR_ENC_START: u32 = 0x14;

/// CPTRA_FW_ERROR_ENC Register End Address
const CPTRA_FW_ERROR_ENC_END: u32 = 0x17;

/// CPTRA_FW_EXTENDED_ERROR_INFO Register Start Address
const CPTRA_FW_EXTENDED_ERROR_INFO_START: u32 = 0x18;

/// CPTRA_FW_EXTENDED_ERROR_INFO Register End Address
const CPTRA_FW_EXTENDED_ERROR_INFO_END: u32 = 0x37;

/// CPTRA_FW_EXTENDED_ERROR_INFO Register Size
const CPTRA_FW_EXTENDED_ERROR_INFO_SIZE: usize = 32;

/// CPTRA_BOOT_STATUS Register Start Address
const CPTRA_BOOT_STATUS_START: u32 = 0x38;

/// CPTRA_BOOT_STATUS Register End Address
const CPTRA_BOOT_STATUS_END: u32 = 0x3b;

/// CPTRA_FLOW_STATUS Register Start Address
const CPTRA_FLOW_STATUS_START: u32 = 0x3c;

/// CPTRA_FLOW_STATUS Register End Address
const CPTRA_FLOW_STATUS_END: u32 = 0x3f;

/// CPTRA_RESET_REASON Register Start Address
const CPTRA_RESET_REASON_START: u32 = 0x40;

/// CPTRA_RESET_REASON Register End Address
const CPTRA_RESET_REASON_END: u32 = 0x43;

/// CPTRA_SECURITY_STATE Register Start Address
const CPTRA_SECURITY_STATE_START: u32 = 0x44;

/// CPTRA_SECURITY_STATE Register End Address
const CPTRA_SECURITY_STATE_END: u32 = 0x47;

/// CPTRA_VALID_PAUSER Register Start Address
const CPTRA_VALID_PAUSER_START: u32 = 0x48;

/// CPTRA_VALID_PAUSER Register End Address
const CPTRA_VALID_PAUSER_END: u32 = 0x5b;

/// CPTRA_VALID_PAUSER Register Size
const CPTRA_VALID_PAUSER_SIZE: usize = 20;

/// CPTRA_PAUSER_LOCK Register Start Address
const CPTRA_PAUSER_LOCK_START: u32 = 0x5c;

/// CPTRA_PAUSER_LOCK Register End Address
const CPTRA_PAUSER_LOCK_END: u32 = 0x6f;

/// CPTRA_PAUSER_LOCK Register Size
const CPTRA_PAUSER_LOCK_SIZE: usize = 20;

/// CPTRA_TRNG_VALID_PAUSER Register Start Address
const CPTRA_TRNG_VALID_PAUSER_START: u32 = 0x70;

/// CPTRA_TRNG_VALID_PAUSER Register End Address
const CPTRA_TRNG_VALID_PAUSER_END: u32 = 0x73;

/// CPTRA_TRNG_PAUSER_LOCK Register Start Address
const CPTRA_TRNG_PAUSER_LOCK_START: u32 = 0x74;

/// CPTRA_TRNG_PAUSER_LOCK Register End Address
const CPTRA_TRNG_PAUSER_LOCK_END: u32 = 0x77;

/// CPTRA_TRNG_DATA Register Start Address
const CPTRA_TRNG_DATA_START: u32 = 0x78;

/// CPTRA_TRNG_DATA Register End Address
const CPTRA_TRNG_DATA_END: u32 = 0xa7;

/// CPTRA_TRNG_DATA Register Size
const CPTRA_TRNG_DATA_SIZE: usize = 48;

/// CPTRA_TRNG_STATUS Register Start Address
const CPTRA_TRNG_STATUS_START: u32 = 0xa8;

/// CPTRA_TRNG_STATUS Register End Address
const CPTRA_TRNG_STATUS_END: u32 = 0xab;

/// CPTRA_FUSE_WR_DONE Register Start Address
const CPTRA_FUSE_WR_DONE_START: u32 = 0xac;

/// CPTRA_FUSE_WR_DONE Register End Address
const CPTRA_FUSE_WR_DONE_END: u32 = 0xaf;

/// CPTRA_TIMER_CONFIG Register Start Address
const CPTRA_TIMER_CONFIG_START: u32 = 0xb0;

/// CPTRA_TIMER_CONFIG Register End Address
const CPTRA_TIMER_CONFIG_END: u32 = 0xb3;

/// CPTRA_BOOTFSM_GO Register Start Address
const CPTRA_BOOTFSM_GO_START: u32 = 0xb4;

/// CPTRA_BOOTFSM_GO Register End Address
const CPTRA_BOOTFSM_GO_END: u32 = 0xb7;

/// CPTRA_DBG_MANUF_SERVICE_REG Register Start Address
const CPTRA_DBG_MANUF_SERVICE_REG_START: u32 = 0xb8;

/// CPTRA_DBG_MANUF_SERVICE_REG Register End Address
const CPTRA_DBG_MANUF_SERVICE_REG_END: u32 = 0xbb;

/// CPTRA_CLK_GATING_EN Register Start Address
const CPTRA_CLK_GATING_EN_START: u32 = 0xbc;

/// CPTRA_CLK_GATING_EN Register End Address
const CPTRA_CLK_GATING_EN_END: u32 = 0xbf;

/// CPTRA_GENERIC_INPUT_WIRES Register Start Address
const CPTRA_GENERIC_INPUT_WIRES_START: u32 = 0xc0;

/// CPTRA_GENERIC_INPUT_WIRES Register End Address
const CPTRA_GENERIC_INPUT_WIRES_END: u32 = 0xc7;

/// CPTRA_GENERIC_INPUT_WIRES Register Size
const CPTRA_GENERIC_INPUT_WIRES_SIZE: usize = 8;

/// CPTRA_GENERIC_OUTPUT_WIRES Register Start Address
const CPTRA_GENERIC_OUTPUT_WIRES_START: u32 = 0xc8;

/// CPTRA_GENERIC_OUTPUT_WIRES Register End Address
const CPTRA_GENERIC_OUTPUT_WIRES_END: u32 = 0xcf;

/// CPTRA_GENERIC_OUTPUT_WIRES Register Size
const CPTRA_GENERIC_OUTPUT_WIRES_SIZE: usize = 8;

/// FUSE_UDS_SEED Register Size
const FUSE_UDS_SEED_SIZE: usize = 48;

/// FUSE_FIELD_ENTROPY Register Size
const FUSE_FIELD_ENTROPY_SIZE: usize = 32;

/// FUSE_VENDOR_PK_HASH Register Start Address
const FUSE_VENDOR_PK_HASH_START: u32 = 0x250;

/// FUSE_VENDOR_PK_HASH Register End Address
const FUSE_VENDOR_PK_HASH_END: u32 = 0x27f;

/// FUSE_VENDOR_PK_HASH Register Size
const FUSE_VENDOR_PK_HASH_SIZE: usize = 48;

/// FUSE_VENDOR_PK_MASK Register Start Address
const FUSE_VENDOR_PK_MASK_START: u32 = 0x280;

/// FUSE_VENDOR_PK_MASK Register End Address
const FUSE_VENDOR_PK_MASK_END: u32 = 0x283;

/// FUSE_OWNER_PK_HASH Register Start Address
const FUSE_OWNER_PK_HASH_START: u32 = 0x284;

/// FUSE_OWNER_PK_HASH Register End Address
const FUSE_OWNER_PK_HASH_END: u32 = 0x2b3;

/// FUSE_OWNER_PK_HASH Register Size
const FUSE_OWNER_PK_HASH_SIZE: usize = 48;

/// FUSE_FMC_SVN Register Start Address
const FUSE_FMC_SVN_START: u32 = 0x2b4;

/// FUSE_FMC_SVN Register End Address
const FUSE_FMC_SVN_END: u32 = 0x2b7;

/// FUSE_RUNTIME_SVN Register Start Address
const FUSE_RUNTIME_SVN_START: u32 = 0x2b8;

/// FUSE_RUNTIME_SVN Register End Address
const FUSE_RUNTIME_SVN_END: u32 = 0x2c7;

/// FUSE_RUNTIME_SVN Register Size
const FUSE_RUNTIME_SVN_SIZE: usize = 16;

/// FUSE_ANTI_ROLLBACK_DISABLE Register Start Address
const FUSE_ANTI_ROLLBACK_DISABLE_START: u32 = 0x2c8;

/// FUSE_ANTI_ROLLBACK_DISABLE Register End Address
const FUSE_ANTI_ROLLBACK_DISABLE_END: u32 = 0x2cb;

/// FUSE_IDEVID_CERT_ATTR Register Start Address
const FUSE_IDEVID_CERT_ATTR_START: u32 = 0x2cc;

/// FUSE_IDEVID_CERT_ATTR Register End Address
const FUSE_IDEVID_CERT_ATTR_END: u32 = 0x32b;

/// FUSE_IDEVID_CERT_ATTR Register Size
const FUSE_IDEVID_CERT_ATTR_SIZE: usize = 96;

/// FUSE_IDEVID_MANUF_HSM_ID Register Start Address
const FUSE_IDEVID_MANUF_HSM_ID_START: u32 = 0x32c;

/// FUSE_IDEVID_MANUF_HSM_ID Register End Address
const FUSE_IDEVID_MANUF_HSM_ID_END: u32 = 0x33b;

/// FUSE_IDEVID_MANUF_HSM_ID Register Size
const FUSE_IDEVID_MANUF_HSM_ID_SIZE: usize = 16;

/// FUSE_LIFE_CYCLE Register Start Address
const FUSE_LIFE_CYCLE_START: u32 = 0x33c;

/// FUSE_LIFE_CYCLE Register End Address
const FUSE_LIFE_CYCLE_END: u32 = 0x33f;

/// INTERNAL_OBF_KEY Register Size
const INTERNAL_OBF_KEY_SIZE: usize = 32;

/// INTERNAL_ICCM_LOCK Register Start Address
const INTERNAL_ICCM_LOCK_START: u32 = 0x620;

/// INTERNAL_ICCM_LOCK Register End Address
const INTERNAL_ICCM_LOCK_END: u32 = 0x623;

/// INTERNAL_FW_UPDATE_RESET Register Start Address
const INTERNAL_FW_UPDATE_RESET_START: u32 = 0x624;

/// INTERNAL_FW_UPDATE_RESET Register End Address
const INTERNAL_FW_UPDATE_RESET_END: u32 = 0x627;

/// INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES Register Start Address
const INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_START: u32 = 0x628;

/// INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES Register End Address
const INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_END: u32 = 0x62b;

/// INTERNAL_NMI_VECTOR Register Start Address
const INTERNAL_NMI_VECTOR_START: u32 = 0x62c;

/// INTERNAL_NMI_VECTOR Register End Address
const INTERNAL_NMI_VECTOR_END: u32 = 0x62f;

register_bitfields! [
    u32,

    /// Flow Status
    FlowStatus [
        STATUS OFFSET(0) NUMBITS(26) [],
        LDEVID_CERT_READY OFFSET(26) NUMBITS(1) [],
        IDEVID_CSR_READY OFFSET(27) NUMBITS(1) [],
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
           PRODUCTION = 0b11,
        ],
        DEBUG_LOCKED OFFSET(2) NUMBITS(1) [],
        SCAN_MODE OFFSET(3) NUMBITS(1) [],
        RSVD OFFSET(4) NUMBITS(28) [],
    ],

    /// Key Manifest Public Key Mask
    VendorPubKeyMask [
        MASK OFFSET(0) NUMBITS(4) [],
        RSVD OFFSET(4) NUMBITS(28) [],
    ],

    /// Anti Rollback Disable
    AntiRollbackDisable [
        DISABLE OFFSET(0) NUMBITS(1) [],
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

    /// Debug Manufacturing Service Register
    DebugManufService [
        REQ_IDEVID_CSR OFFSET(0) NUMBITS(1) [],
        REQ_LDEVID_CERT OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
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
    pub fn new(clock: &Clock, mailbox: Mailbox, iccm: Iccm, args: CaliptraRootBusArgs) -> Self {
        Self {
            regs: Rc::new(RefCell::new(SocRegistersImpl::new(
                clock, mailbox, iccm, args,
            ))),
        }
    }

    /// Get Unique device secret
    pub fn uds(&self) -> [u8; FUSE_UDS_SEED_SIZE] {
        *self.regs.borrow().fuse_uds_seed.data()
    }

    // Get field entropy
    pub fn field_entropy(&self) -> [u8; FUSE_FIELD_ENTROPY_SIZE] {
        *self.regs.borrow().fuse_field_entropy.data()
    }

    /// Get deobfuscation engine key
    pub fn doe_key(&self) -> [u8; INTERNAL_OBF_KEY_SIZE] {
        *self.regs.borrow().internal_obf_key.data()
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

    fn poll(&mut self) {
        self.regs.borrow_mut().poll();
    }
}

/// SOC Register implementation

struct SocRegistersImpl {
    /// CPTRA_HW_ERROR_FATAL Register
    cptra_hw_error_fatal: ReadWriteRegister<u32>,

    /// CPTRA_HW_ERROR_NON_FATAL Register
    cptra_hw_error_non_fatal: ReadWriteRegister<u32>,

    /// CPTRA_FW_ERROR_FATAL Register
    cptra_fw_error_fatal: ReadWriteRegister<u32>,

    /// CPTRA_FW_ERROR_NON_FATAL Register
    cptra_fw_error_non_fatal: ReadWriteRegister<u32>,

    /// CPTRA_HW_ERROR_ENC Register
    cptra_hw_error_enc: ReadWriteRegister<u32>,

    /// CPTRA_FW_ERROR_ENC Register
    cptra_fw_error_enc: ReadWriteRegister<u32>,

    /// CPTRA_FW_EXTENDED_ERROR_INFO Register
    cptra_fw_extended_error_info: ReadWriteMemory<CPTRA_FW_EXTENDED_ERROR_INFO_SIZE>,

    /// CPTRA_BOOT_STATUS Register
    cptra_boot_status: ReadWriteRegister<u32>,

    /// CPTRA_FLOW_STATUS Register
    cptra_flow_status: ReadWriteRegister<u32, FlowStatus::Register>,

    /// CPTRA_RESET_REASON Register
    cptra_reset_reason: ReadOnlyRegister<u32>,

    /// CPTRA_SECURITY_STATE Register
    cptra_security_state: ReadOnlyRegister<u32, SecurityState::Register>,

    /// CPTRA_VALID_PAUSER Register
    cptra_valid_pauser: ReadWriteMemory<CPTRA_VALID_PAUSER_SIZE>,

    /// CPTRA_PAUSER_LOCK Register
    cptra_pauser_lock: ReadWriteMemory<CPTRA_PAUSER_LOCK_SIZE>,

    /// CPTRA_TRNG_VALID_PAUSER Register
    cptra_trng_valid_pauser: ReadWriteRegister<u32>,

    /// CPTRA_TRNG_PAUSER_LOCK Register
    cptra_trng_pauser_lock: ReadWriteRegister<u32>,

    /// CPTRA_TRNG_DATA Register
    cptra_trng_data: ReadOnlyMemory<CPTRA_TRNG_DATA_SIZE>,

    /// CPTRA_TRNG_STATUS Register
    cptra_trng_status: ReadOnlyRegister<u32>,

    /// CPTRA_FUSE_WR_DONE Register
    cptra_fuse_wr_done: ReadOnlyRegister<u32>,

    /// CPTRA_TIMER_CONFIG Register
    cptra_timer_config: ReadWriteRegister<u32>,

    /// CPTRA_BOOTFSM_GO Register
    cptra_bootfsm_go: ReadOnlyRegister<u32>,

    /// CPTRA_DBG_MANUF_SERVICE_REG Register
    cptra_dbg_manuf_service_reg: ReadWriteRegister<u32, DebugManufService::Register>,

    /// CPTRA_CLK_GATING_EN Register
    cptra_clk_gating_en: ReadOnlyRegister<u32>,

    /// CPTRA_GENERIC_INPUT_WIRES Register
    cptra_generic_input_wires: ReadOnlyMemory<CPTRA_GENERIC_INPUT_WIRES_SIZE>,

    /// CPTRA_GENERIC_OUTPUT_WIRES Register
    cptra_generic_output_wires: ReadWriteMemory<CPTRA_GENERIC_OUTPUT_WIRES_SIZE>,

    /// FUSE_UDS_SEED Register
    fuse_uds_seed: ReadOnlyMemory<FUSE_UDS_SEED_SIZE>,

    /// FUSE_FIELD_ENTROPY Register
    fuse_field_entropy: ReadOnlyMemory<FUSE_FIELD_ENTROPY_SIZE>,

    /// FUSE_VENDOR_PK_HASH Register
    fuse_vendor_pk_hash: ReadOnlyMemory<FUSE_VENDOR_PK_HASH_SIZE>,

    /// FUSE_VENDOR_PK_MASK Register
    fuse_vendor_pk_hash_mask: ReadOnlyRegister<u32, VendorPubKeyMask::Register>,

    /// FUSE_OWNER_PK_HASH Register
    fuse_owner_pk_hash: ReadOnlyMemory<FUSE_OWNER_PK_HASH_SIZE>,

    /// FUSE_FMC_SVN Register
    fuse_fmc_svn: ReadOnlyRegister<u32>,

    /// FUSE_RUNTIME_SVN Register
    fuse_runtime_svn: ReadOnlyMemory<FUSE_RUNTIME_SVN_SIZE>,

    /// FUSE_ANTI_ROLLBACK_DISABLE Register
    fuse_anti_rollback_disable: ReadOnlyRegister<u32>,

    /// FUSE_IDEVID_CERT_ATTR Register
    fuse_idevid_cert_attr: ReadOnlyMemory<FUSE_IDEVID_CERT_ATTR_SIZE>,

    /// FUSE_IDEVID_MANUF_HSM_ID Register
    fuse_idevid_manuf_hsm_id: ReadOnlyMemory<FUSE_IDEVID_MANUF_HSM_ID_SIZE>,

    /// FUSE_LIFE_CYCLE Register
    fuse_life_cycle: ReadOnlyRegister<u32>,

    /// INTERNAL_OBF_KEY Register
    internal_obf_key: ReadOnlyMemory<INTERNAL_OBF_KEY_SIZE>,

    /// INTERNAL_ICCM_LOCK Register
    internal_iccm_lock: ReadWriteRegister<u32, IccmLock::Register>,

    /// INTERNAL_FW_UPDATE_RESET Register
    internal_fw_update_reset: ReadWriteRegister<u32, FwUpdateReset::Register>,

    /// INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES Register
    internal_fw_update_reset_wait_cycles: ReadWriteRegister<u32, FwUpdateResetWaitCycles::Register>,

    /// INTERNAL_NMI_VECTOR Register
    internal_nmi_vector: ReadWriteRegister<u32>,

    /// Mailbox
    mailbox: Mailbox,

    /// ICCM
    iccm: Iccm,

    /// Log Directory
    log_dir: PathBuf,

    /// Timer
    timer: Timer,

    /// Firmware Write Complete action
    op_fw_write_complete_action: Option<TimerAction>,

    /// Firmware Read Complete action
    op_fw_read_complete_action: Option<TimerAction>,

    /// IDEVID CSR Read Complete action
    op_idevid_csr_read_complete_action: Option<TimerAction>,

    /// LDEVID Cert Read Complete action
    op_ldevid_cert_read_complete_action: Option<TimerAction>,

    /// test bench services callback
    tb_services_cb: Box<dyn FnMut(u8)>,

    ready_for_fw_cb: ReadyForFwCallback,
}

impl SocRegistersImpl {
    /// Default Deobfuscation engine key
    const DOE_KEY: [u8; INTERNAL_OBF_KEY_SIZE] = [
        0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77,
        0x81, 0x1F, 0x35, 0x2C, 0x7, 0x3B, 0x61, 0x8, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x9, 0x14,
        0xDF, 0xF4,
    ];

    /// Default unique device secret
    const UDS: [u8; FUSE_UDS_SEED_SIZE] = [
        0xF5, 0x8C, 0x4C, 0x4, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB,
        0xD6, 0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70,
        0x2C, 0x7D, 0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x4,
        0x23, 0x14, 0x61,
    ];

    /// The number of CPU clock cycles it takes to write the firmware to the mailbox.
    const FW_WRITE_TICKS: u64 = 1000;

    /// The number of CPU clock cycles it takes to read the firmware from the mailbox.
    const FW_READ_TICKS: u64 = 0;

    /// The number of CPU clock cycles it takes to read the IDEVID CSR from the mailbox.
    const IDEVID_CSR_READ_TICKS: u64 = 100;

    /// The number of CPU clock cycles it takes to read the LDEVID Cert from the mailbox.
    const LDEVID_CERT_READ_TICKS: u64 = 300;

    pub fn new(clock: &Clock, mailbox: Mailbox, iccm: Iccm, mut args: CaliptraRootBusArgs) -> Self {
        let mut regs = Self {
            cptra_hw_error_fatal: ReadWriteRegister::new(0),
            cptra_hw_error_non_fatal: ReadWriteRegister::new(0),
            cptra_fw_error_fatal: ReadWriteRegister::new(0),
            cptra_fw_error_non_fatal: ReadWriteRegister::new(0),
            cptra_hw_error_enc: ReadWriteRegister::new(0),
            cptra_fw_error_enc: ReadWriteRegister::new(0),
            cptra_fw_extended_error_info: ReadWriteMemory::new(),
            cptra_boot_status: ReadWriteRegister::new(0),
            cptra_flow_status: ReadWriteRegister::new(0),
            cptra_reset_reason: ReadOnlyRegister::new(0),
            cptra_security_state: ReadOnlyRegister::new(0),
            cptra_valid_pauser: ReadWriteMemory::new(),
            cptra_pauser_lock: ReadWriteMemory::new(),
            cptra_trng_valid_pauser: ReadWriteRegister::new(0),
            cptra_trng_pauser_lock: ReadWriteRegister::new(0),
            cptra_trng_data: ReadOnlyMemory::new(),
            cptra_trng_status: ReadOnlyRegister::new(0),
            cptra_fuse_wr_done: ReadOnlyRegister::new(0),
            cptra_timer_config: ReadWriteRegister::new(0),
            cptra_bootfsm_go: ReadOnlyRegister::new(0),
            cptra_dbg_manuf_service_reg: ReadWriteRegister::new(0),
            cptra_clk_gating_en: ReadOnlyRegister::new(0),
            cptra_generic_input_wires: ReadOnlyMemory::new(),
            cptra_generic_output_wires: ReadWriteMemory::new(),
            fuse_uds_seed: ReadOnlyMemory::new_with_data(Self::UDS),
            fuse_field_entropy: ReadOnlyMemory::new_with_data([0xFF; 32]),
            fuse_vendor_pk_hash: ReadOnlyMemory::new(),
            fuse_vendor_pk_hash_mask: ReadOnlyRegister::new(0),
            fuse_owner_pk_hash: ReadOnlyMemory::new(),
            fuse_fmc_svn: ReadOnlyRegister::new(0),
            fuse_runtime_svn: ReadOnlyMemory::new(),
            fuse_anti_rollback_disable: ReadOnlyRegister::new(0),
            fuse_idevid_cert_attr: ReadOnlyMemory::new(),
            fuse_idevid_manuf_hsm_id: ReadOnlyMemory::new(),
            fuse_life_cycle: ReadOnlyRegister::new(0),
            internal_obf_key: ReadOnlyMemory::new_with_data(Self::DOE_KEY),
            internal_iccm_lock: ReadWriteRegister::new(0),
            internal_fw_update_reset: ReadWriteRegister::new(0),
            internal_fw_update_reset_wait_cycles: ReadWriteRegister::new(0),
            internal_nmi_vector: ReadWriteRegister::new(0),
            mailbox,
            iccm,
            log_dir: args.log_dir.clone(),
            timer: Timer::new(clock),
            op_fw_write_complete_action: None,
            op_fw_read_complete_action: None,
            op_idevid_csr_read_complete_action: None,
            op_ldevid_cert_read_complete_action: None,
            tb_services_cb: args.tb_services_cb.take(),
            ready_for_fw_cb: args.ready_for_fw_cb.take(),
        };

        regs.set_cptra_dbg_manuf_service_reg(&args);
        regs.set_idevid_cert_attr(&args);
        regs.set_fuse_vendor_pk_hash(&args);
        regs.set_fuse_owner_pk_hash(&args);
        regs.set_cptra_security_state_device_lifecycle(&args);

        regs
    }

    fn set_fuse_vendor_pk_hash(&mut self, args: &CaliptraRootBusArgs) {
        if args.mfg_pk_hash.len() == FUSE_VENDOR_PK_HASH_SIZE {
            self.fuse_vendor_pk_hash
                .data_mut()
                .copy_from_slice(array_ref![args.mfg_pk_hash, 0, FUSE_VENDOR_PK_HASH_SIZE]);
        }
    }

    fn set_fuse_owner_pk_hash(&mut self, args: &CaliptraRootBusArgs) {
        if args.owner_pk_hash.len() == FUSE_OWNER_PK_HASH_SIZE {
            self.fuse_owner_pk_hash
                .data_mut()
                .copy_from_slice(array_ref![args.owner_pk_hash, 0, FUSE_OWNER_PK_HASH_SIZE]);
        }
    }

    fn set_cptra_security_state_device_lifecycle(&mut self, args: &CaliptraRootBusArgs) {
        let mut value = SecurityState::LIFE_CYCLE::UNPROVISIONED;
        if args.device_lifecycle.eq_ignore_ascii_case("manufacturing") {
            value = SecurityState::LIFE_CYCLE::MANUFACTURING;
        } else if args.device_lifecycle.eq_ignore_ascii_case("production") {
            value = SecurityState::LIFE_CYCLE::PRODUCTION;
        }
        self.cptra_security_state
            .reg
            .modify(SecurityState::LIFE_CYCLE.val(value.read(SecurityState::LIFE_CYCLE)));
    }

    fn set_cptra_dbg_manuf_service_reg(&mut self, args: &CaliptraRootBusArgs) {
        register_bitfields! [
            u32,
            DebugManufService [
                GEN_IDEVID_CSR OFFSET(0) NUMBITS(1) [],
                GEN_LDEVID_CERT OFFSET(1) NUMBITS(1) [],
                RESERVED OFFSET(2) NUMBITS(30) [],
            ],
        ];
        let reg: InMemoryRegister<u32, DebugManufService::Register> = InMemoryRegister::new(0);

        if args.req_idevid_csr {
            reg.modify(DebugManufService::GEN_IDEVID_CSR::SET);
        }

        if args.req_ldevid_cert {
            reg.modify(DebugManufService::GEN_LDEVID_CERT::SET);
        }

        self.cptra_dbg_manuf_service_reg.reg.set(reg.get());
    }

    fn set_idevid_cert_attr(&mut self, args: &CaliptraRootBusArgs) {
        register_bitfields! [
            u32,
            IDevIdCertAttrFlags [
                KEY_ID_ALGO OFFSET(0) NUMBITS(2) [
                    SHA1 = 0b00,
                    SHA256 = 0b01,
                    SHA384 = 0b10,
                    FUSE = 0b11,
                ],
                RESERVED OFFSET(2) NUMBITS(30) [],
            ],
        ];

        // Determine the Algorithm used for IDEVID Certificate Subject Key Identifier
        let reg: InMemoryRegister<u32, IDevIdCertAttrFlags::Register> = InMemoryRegister::new(0);
        if args.idev_key_id_algo.eq_ignore_ascii_case("sha1") {
            reg.write(IDevIdCertAttrFlags::KEY_ID_ALGO::SHA1)
        } else if args.idev_key_id_algo.eq_ignore_ascii_case("sha256") {
            reg.write(IDevIdCertAttrFlags::KEY_ID_ALGO::SHA256)
        } else if args.idev_key_id_algo.eq_ignore_ascii_case("sha384") {
            reg.write(IDevIdCertAttrFlags::KEY_ID_ALGO::SHA384)
        } else if args.idev_key_id_algo.eq_ignore_ascii_case("fuse") {
            reg.write(IDevIdCertAttrFlags::KEY_ID_ALGO::FUSE)
        } else {
            reg.write(IDevIdCertAttrFlags::KEY_ID_ALGO::SHA1)
        }

        // DWORD 00      - Flags
        self.fuse_idevid_cert_attr.data_mut()[0..4].copy_from_slice(&reg.get().to_le_bytes());

        // DWORD 01 - 05 - IDEVID Subject Key Identifier
        self.fuse_idevid_cert_attr.data_mut()[4..24].copy_from_slice(&[0x00; 20]);

        // DWORD 06 - 07 - UEID / Manufacturer Serial Number
        let ueid = args.ueid.to_le_bytes();
        self.fuse_idevid_cert_attr.data_mut()[24..28].copy_from_slice(&ueid[..4]);
        self.fuse_idevid_cert_attr.data_mut()[28..32].copy_from_slice(&ueid[4..]);
    }

    /// Clear secrets
    fn clear_secrets(&mut self) {
        self.fuse_uds_seed.data_mut().fill(0);
        self.fuse_field_entropy.data_mut().fill(0);
        self.internal_obf_key.data_mut().fill(0);
    }

    /// On Write callback for `stdout` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn on_write_tb_services(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        let val = (val & 0xFF) as u8;

        (self.tb_services_cb)(val);

        Ok(())
    }

    /// On Write callback for `flow_status` register
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn on_write_flow_status(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        // Writes have to be Word aligned.
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // Set the flow status register.
        self.cptra_flow_status.reg.set(val);

        // If ready_for_fw bit is set, upload the firmware image to the mailbox.
        if self.cptra_flow_status.reg.is_set(FlowStatus::READY_FOR_FW) {
            while !self.mailbox.try_acquire_lock() {}
            self.op_fw_write_complete_action =
                Some(self.timer.schedule_poll_in(Self::FW_WRITE_TICKS));
        } else if self
            .cptra_flow_status
            .reg
            .is_set(FlowStatus::IDEVID_CSR_READY)
        {
            self.op_idevid_csr_read_complete_action =
                Some(self.timer.schedule_poll_in(Self::IDEVID_CSR_READ_TICKS));
        } else if self
            .cptra_flow_status
            .reg
            .is_set(FlowStatus::LDEVID_CERT_READY)
        {
            self.op_ldevid_cert_read_complete_action =
                Some(self.timer.schedule_poll_in(Self::LDEVID_CERT_READ_TICKS));
        }

        Ok(())
    }

    fn download_idev_id_csr(&mut self) {
        if !self.mailbox.is_status_data_ready() {
            return;
        }

        self.download_to_file("caliptra_idevid_csr.der");

        self.cptra_dbg_manuf_service_reg
            .reg
            .modify(DebugManufService::REQ_IDEVID_CSR::CLEAR);
    }

    fn download_ldev_id_cert(&mut self) {
        if !self.mailbox.is_status_data_ready() {
            return;
        }

        self.download_to_file("caliptra_ldevid_cert.der");

        self.cptra_dbg_manuf_service_reg
            .reg
            .modify(DebugManufService::REQ_LDEVID_CERT::CLEAR);
    }

    fn download_to_file(&mut self, file: &str) {
        let mut path = self.log_dir.clone();
        path.push(file);
        let mut file = std::fs::File::create(path).unwrap();

        let byte_count = self.mailbox.read_dlen().unwrap() as usize;
        let remainder = byte_count % core::mem::size_of::<u32>();
        let n = byte_count - remainder;

        for _ in (0..n).step_by(core::mem::size_of::<u32>()) {
            let buf = self.mailbox.read_dataout().unwrap();
            file.write_all(&buf.to_le_bytes()).unwrap();
        }

        if remainder > 0 {
            let part = self.mailbox.read_dataout().unwrap();
            for idx in 0..remainder {
                let byte = ((part >> (idx << 3)) & 0xFF) as u8;
                file.write_all(&[byte]).unwrap();
            }
        }
    }
}

impl Bus for SocRegistersImpl {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            CPTRA_HW_ERROR_FATAL_START..=CPTRA_HW_ERROR_FATAL_END => {
                self.cptra_hw_error_fatal.read(size)
            }

            CPTRA_HW_ERROR_NON_FATAL_START..=CPTRA_HW_ERROR_NON_FATAL_END => {
                self.cptra_hw_error_non_fatal.read(size)
            }

            CPTRA_FW_ERROR_FATAL_START..=CPTRA_FW_ERROR_FATAL_END => {
                self.cptra_fw_error_fatal.read(size)
            }

            CPTRA_FW_ERROR_NON_FATAL_START..=CPTRA_FW_ERROR_NON_FATAL_END => {
                self.cptra_fw_error_non_fatal.read(size)
            }

            CPTRA_HW_ERROR_ENC_START..=CPTRA_HW_ERROR_ENC_END => self.cptra_hw_error_enc.read(size),

            CPTRA_FW_ERROR_ENC_START..=CPTRA_FW_ERROR_ENC_END => self.cptra_fw_error_enc.read(size),

            CPTRA_FW_EXTENDED_ERROR_INFO_START..=CPTRA_FW_EXTENDED_ERROR_INFO_END => self
                .cptra_fw_extended_error_info
                .read(size, addr - CPTRA_FW_EXTENDED_ERROR_INFO_START),

            CPTRA_BOOT_STATUS_START..=CPTRA_BOOT_STATUS_END => self.cptra_boot_status.read(size),

            CPTRA_FLOW_STATUS_START..=CPTRA_FLOW_STATUS_END => self.cptra_flow_status.read(size),

            CPTRA_RESET_REASON_START..=CPTRA_RESET_REASON_END => self.cptra_reset_reason.read(size),

            CPTRA_SECURITY_STATE_START..=CPTRA_SECURITY_STATE_END => {
                self.cptra_security_state.read(size)
            }

            CPTRA_VALID_PAUSER_START..=CPTRA_VALID_PAUSER_END => self
                .cptra_valid_pauser
                .read(size, addr - CPTRA_VALID_PAUSER_START),

            CPTRA_PAUSER_LOCK_START..=CPTRA_PAUSER_LOCK_END => self
                .cptra_pauser_lock
                .read(size, addr - CPTRA_PAUSER_LOCK_START),

            CPTRA_TRNG_VALID_PAUSER_START..=CPTRA_TRNG_VALID_PAUSER_END => {
                self.cptra_trng_valid_pauser.read(size)
            }

            CPTRA_TRNG_PAUSER_LOCK_START..=CPTRA_TRNG_PAUSER_LOCK_END => {
                self.cptra_trng_pauser_lock.read(size)
            }

            CPTRA_TRNG_DATA_START..=CPTRA_TRNG_DATA_END => self
                .cptra_trng_data
                .read(size, addr - CPTRA_TRNG_DATA_START),

            CPTRA_TRNG_STATUS_START..=CPTRA_TRNG_STATUS_END => self.cptra_trng_status.read(size),

            CPTRA_FUSE_WR_DONE_START..=CPTRA_FUSE_WR_DONE_END => self.cptra_fuse_wr_done.read(size),

            CPTRA_TIMER_CONFIG_START..=CPTRA_TIMER_CONFIG_END => self.cptra_timer_config.read(size),

            CPTRA_BOOTFSM_GO_START..=CPTRA_BOOTFSM_GO_END => self.cptra_bootfsm_go.read(size),

            CPTRA_DBG_MANUF_SERVICE_REG_START..=CPTRA_DBG_MANUF_SERVICE_REG_END => {
                self.cptra_dbg_manuf_service_reg.read(size)
            }

            CPTRA_CLK_GATING_EN_START..=CPTRA_CLK_GATING_EN_END => {
                self.cptra_clk_gating_en.read(size)
            }

            CPTRA_GENERIC_INPUT_WIRES_START..=CPTRA_GENERIC_INPUT_WIRES_END => self
                .cptra_generic_input_wires
                .read(size, addr - CPTRA_GENERIC_INPUT_WIRES_START),

            CPTRA_GENERIC_OUTPUT_WIRES_START..=CPTRA_GENERIC_OUTPUT_WIRES_END => self
                .cptra_generic_output_wires
                .read(size, addr - CPTRA_GENERIC_OUTPUT_WIRES_START),

            FUSE_VENDOR_PK_HASH_START..=FUSE_VENDOR_PK_HASH_END => self
                .fuse_vendor_pk_hash
                .read(size, addr - FUSE_VENDOR_PK_HASH_START),

            FUSE_VENDOR_PK_MASK_START..=FUSE_VENDOR_PK_MASK_END => {
                self.fuse_vendor_pk_hash_mask.read(size)
            }

            FUSE_OWNER_PK_HASH_START..=FUSE_OWNER_PK_HASH_END => self
                .fuse_owner_pk_hash
                .read(size, addr - FUSE_OWNER_PK_HASH_START),

            FUSE_FMC_SVN_START..=FUSE_FMC_SVN_END => self.fuse_fmc_svn.read(size),

            FUSE_RUNTIME_SVN_START..=FUSE_RUNTIME_SVN_END => self
                .fuse_runtime_svn
                .read(size, addr - FUSE_RUNTIME_SVN_START),

            FUSE_ANTI_ROLLBACK_DISABLE_START..=FUSE_ANTI_ROLLBACK_DISABLE_END => {
                self.fuse_anti_rollback_disable.read(size)
            }

            FUSE_IDEVID_CERT_ATTR_START..=FUSE_IDEVID_CERT_ATTR_END => self
                .fuse_idevid_cert_attr
                .read(size, addr - FUSE_IDEVID_CERT_ATTR_START),

            FUSE_IDEVID_MANUF_HSM_ID_START..=FUSE_IDEVID_MANUF_HSM_ID_END => self
                .fuse_idevid_manuf_hsm_id
                .read(size, addr - FUSE_IDEVID_MANUF_HSM_ID_START),

            FUSE_LIFE_CYCLE_START..=FUSE_LIFE_CYCLE_END => self.fuse_life_cycle.read(size),

            INTERNAL_ICCM_LOCK_START..=INTERNAL_ICCM_LOCK_END => self.internal_iccm_lock.read(size),

            INTERNAL_FW_UPDATE_RESET_START..=INTERNAL_FW_UPDATE_RESET_END => {
                self.internal_fw_update_reset.read(size)
            }

            INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_START
                ..=INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_END => {
                self.internal_fw_update_reset_wait_cycles.read(size)
            }

            INTERNAL_NMI_VECTOR_START..=INTERNAL_NMI_VECTOR_END => {
                self.internal_nmi_vector.read(size)
            }
            _ => Err(BusError::LoadAccessFault),
        }
    }

    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            CPTRA_HW_ERROR_FATAL_START..=CPTRA_HW_ERROR_FATAL_END => {
                self.cptra_hw_error_fatal.write(size, val)
            }

            CPTRA_HW_ERROR_NON_FATAL_START..=CPTRA_HW_ERROR_NON_FATAL_END => {
                self.cptra_hw_error_non_fatal.write(size, val)
            }

            CPTRA_FW_ERROR_FATAL_START..=CPTRA_FW_ERROR_FATAL_END => {
                self.cptra_fw_error_fatal.write(size, val)
            }

            CPTRA_FW_ERROR_NON_FATAL_START..=CPTRA_FW_ERROR_NON_FATAL_END => {
                self.cptra_fw_error_non_fatal.write(size, val)
            }

            CPTRA_HW_ERROR_ENC_START..=CPTRA_HW_ERROR_ENC_END => {
                self.cptra_hw_error_enc.write(size, val)
            }

            CPTRA_FW_ERROR_ENC_START..=CPTRA_FW_ERROR_ENC_END => {
                self.cptra_fw_error_enc.write(size, val)
            }

            CPTRA_FW_EXTENDED_ERROR_INFO_START..=CPTRA_FW_EXTENDED_ERROR_INFO_END => self
                .cptra_fw_extended_error_info
                .write(size, addr - CPTRA_FW_EXTENDED_ERROR_INFO_START, val),

            CPTRA_BOOT_STATUS_START..=CPTRA_BOOT_STATUS_END => {
                self.cptra_boot_status.write(size, val)
            }

            CPTRA_FLOW_STATUS_START..=CPTRA_FLOW_STATUS_END => self.on_write_flow_status(size, val),

            CPTRA_RESET_REASON_START..=CPTRA_RESET_REASON_END => {
                self.cptra_reset_reason.write(size, val)
            }

            CPTRA_SECURITY_STATE_START..=CPTRA_SECURITY_STATE_END => {
                self.cptra_security_state.write(size, val)
            }

            CPTRA_VALID_PAUSER_START..=CPTRA_VALID_PAUSER_END => {
                self.cptra_valid_pauser
                    .write(size, addr - CPTRA_VALID_PAUSER_START, val)
            }

            CPTRA_PAUSER_LOCK_START..=CPTRA_PAUSER_LOCK_END => {
                self.cptra_pauser_lock
                    .write(size, addr - CPTRA_PAUSER_LOCK_START, val)
            }

            CPTRA_TRNG_VALID_PAUSER_START..=CPTRA_TRNG_VALID_PAUSER_END => {
                self.cptra_trng_valid_pauser.write(size, val)
            }

            CPTRA_TRNG_PAUSER_LOCK_START..=CPTRA_TRNG_PAUSER_LOCK_END => {
                self.cptra_trng_pauser_lock.write(size, val)
            }

            CPTRA_TRNG_DATA_START..=CPTRA_TRNG_DATA_END => {
                self.cptra_trng_data
                    .write(size, addr - CPTRA_TRNG_DATA_START, val)
            }

            CPTRA_TRNG_STATUS_START..=CPTRA_TRNG_STATUS_END => {
                self.cptra_trng_status.write(size, val)
            }

            CPTRA_FUSE_WR_DONE_START..=CPTRA_FUSE_WR_DONE_END => {
                self.cptra_fuse_wr_done.write(size, val)
            }

            CPTRA_TIMER_CONFIG_START..=CPTRA_TIMER_CONFIG_END => {
                self.cptra_timer_config.write(size, val)
            }

            CPTRA_BOOTFSM_GO_START..=CPTRA_BOOTFSM_GO_END => self.cptra_bootfsm_go.write(size, val),

            CPTRA_DBG_MANUF_SERVICE_REG_START..=CPTRA_DBG_MANUF_SERVICE_REG_END => {
                self.cptra_dbg_manuf_service_reg.write(size, val)
            }

            CPTRA_CLK_GATING_EN_START..=CPTRA_CLK_GATING_EN_END => {
                self.cptra_clk_gating_en.write(size, val)
            }

            CPTRA_GENERIC_INPUT_WIRES_START..=CPTRA_GENERIC_INPUT_WIRES_END => self
                .cptra_generic_input_wires
                .write(size, addr - CPTRA_GENERIC_INPUT_WIRES_START, val),

            CPTRA_GENERIC_OUTPUT_WIRES_START..=CPTRA_GENERIC_OUTPUT_WIRES_END => {
                if addr == CPTRA_GENERIC_OUTPUT_WIRES_START {
                    self.on_write_tb_services(size, val)
                } else {
                    self.cptra_generic_output_wires.write(
                        size,
                        addr - CPTRA_GENERIC_OUTPUT_WIRES_START,
                        val,
                    )
                }
            }

            INTERNAL_ICCM_LOCK_START..=INTERNAL_ICCM_LOCK_END => {
                let iccm_lock_reg = InMemoryRegister::<u32, IccmLock::Register>::new(val);
                if iccm_lock_reg.is_set(IccmLock::LOCK) {
                    self.iccm.lock();
                } else {
                    self.iccm.unlock();
                }
                self.internal_iccm_lock.write(size, val)
            }

            INTERNAL_FW_UPDATE_RESET_START..=INTERNAL_FW_UPDATE_RESET_END => {
                self.internal_fw_update_reset.write(size, val)
            }

            INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_START
                ..=INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_END => {
                self.internal_fw_update_reset_wait_cycles.write(size, val)
            }

            INTERNAL_NMI_VECTOR_START..=INTERNAL_NMI_VECTOR_END => {
                self.internal_nmi_vector.write(size, val)
            }
            _ => Err(BusError::LoadAccessFault),
        }
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn poll(&mut self) {
        if self.timer.fired(&mut self.op_fw_write_complete_action) {
            (self.ready_for_fw_cb)(&mut self.mailbox);
            // Schedule a future call to poll() to check on the fw read operation completion.
            self.op_fw_read_complete_action =
                Some(self.timer.schedule_poll_in(Self::FW_READ_TICKS));
        }

        if self.timer.fired(&mut self.op_fw_read_complete_action) {
            // Receiver sets status as CMD_COMPLETE after reading the mailbox data.
            if self.mailbox.is_status_cmd_complete() {
                // Reset the execute bit
                self.mailbox.write_execute(0).unwrap();
            } else {
                self.op_fw_read_complete_action =
                    Some(self.timer.schedule_poll_in(Self::FW_READ_TICKS));
            }
        }

        if self
            .timer
            .fired(&mut self.op_idevid_csr_read_complete_action)
        {
            self.download_idev_id_csr();
        }

        if self
            .timer
            .fired(&mut self.op_ldevid_cert_read_complete_action)
        {
            self.download_ldev_id_cert()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::Path};

    use super::*;
    use crate::{root_bus::TbServicesCb, MailboxRam};
    use tock_registers::registers::InMemoryRegister;

    fn send_data_to_mailbox(mailbox: &mut Mailbox, cmd: u32, data: &[u8]) {
        while !mailbox.try_acquire_lock() {}

        mailbox.write_cmd(cmd).unwrap();
        mailbox.write_dlen(data.len() as u32).unwrap();

        let word_size = RvSize::Word as usize;
        let remainder = data.len() % word_size;
        let n = data.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            mailbox
                .write_datain(u32::from_le_bytes(
                    data[idx..idx + word_size].try_into().unwrap(),
                ))
                .unwrap();
        }

        // Handle the remainder bytes.
        if remainder > 0 {
            let mut last_word = data[n] as u32;
            for idx in 1..remainder {
                last_word |= (data[n + idx] as u32) << (idx << 3);
            }
            mailbox.write_datain(last_word).unwrap();
        }
    }

    #[test]
    fn test_idev_id_csr_download() {
        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mut mailbox = Mailbox::new(mailbox_ram);
        let req_idevid_csr = true;
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        let args = CaliptraRootBusArgs::default();
        let args = CaliptraRootBusArgs {
            req_idevid_csr,
            log_dir,
            ..args
        };
        let mut soc_reg: SocRegisters =
            SocRegisters::new(&clock, mailbox.clone(), Iccm::new(), args);

        //
        // [Sender Side]
        //

        // Add csr data to the mailbox.
        send_data_to_mailbox(&mut mailbox, 0xDEADBEEF, &data);
        mailbox.set_status_data_ready().unwrap();
        mailbox.write_execute(1).unwrap();

        // Trigger csr download.
        let flow_status = InMemoryRegister::<u32, FlowStatus::Register>::new(0);
        flow_status.write(FlowStatus::IDEVID_CSR_READY.val(1));
        assert_eq!(
            soc_reg
                .write(RvSize::Word, CPTRA_FLOW_STATUS_START, flow_status.get())
                .ok(),
            Some(())
        );

        //
        // [Receiver Side]
        //

        // Wait till the idevid csr is downloaded.
        loop {
            clock.increment_and_poll(1, &mut soc_reg);
            let dbg_manuf_service_reg = InMemoryRegister::<u32, DebugManufService::Register>::new(
                soc_reg
                    .read(RvSize::Word, CPTRA_DBG_MANUF_SERVICE_REG_START)
                    .unwrap(),
            );
            if !dbg_manuf_service_reg.is_set(DebugManufService::REQ_IDEVID_CSR) {
                break;
            }
        }

        // Check if the downloaded csr matches.
        let path = "/tmp/caliptra_idevid_csr.der";
        assert!(Path::new(path).exists());
        let mut idevid_csr_buffer = Vec::new();
        let mut idevid_csr_file = File::open(path).unwrap();
        idevid_csr_file.read_to_end(&mut idevid_csr_buffer).unwrap();
        assert_eq!(data, idevid_csr_buffer[..]);
    }

    #[test]
    fn test_ldev_id_cert_download() {
        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mut mailbox = Mailbox::new(mailbox_ram);
        let req_ldevid_cert = true;
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        let args = CaliptraRootBusArgs::default();
        let args = CaliptraRootBusArgs {
            req_ldevid_cert,
            log_dir,
            ..args
        };
        let mut soc_reg: SocRegisters =
            SocRegisters::new(&clock, mailbox.clone(), Iccm::new(), args);

        //
        // [Sender Side]
        //

        // Add cert data to the mailbox.
        send_data_to_mailbox(&mut mailbox, 0xDEADBEEF, &data);
        mailbox.set_status_data_ready().unwrap();
        mailbox.write_execute(1).unwrap();

        // Trigger cert download.
        let flow_status = InMemoryRegister::<u32, FlowStatus::Register>::new(0);
        flow_status.write(FlowStatus::LDEVID_CERT_READY.val(1));
        assert_eq!(
            soc_reg
                .write(RvSize::Word, CPTRA_FLOW_STATUS_START, flow_status.get())
                .ok(),
            Some(())
        );

        //
        // [Receiver Side]
        //

        // Wait till the ldevid cert is downloaded.
        loop {
            clock.increment_and_poll(1, &mut soc_reg);
            let dbg_manuf_service_reg = InMemoryRegister::<u32, DebugManufService::Register>::new(
                soc_reg
                    .read(RvSize::Word, CPTRA_DBG_MANUF_SERVICE_REG_START)
                    .unwrap(),
            );
            if !dbg_manuf_service_reg.is_set(DebugManufService::REQ_LDEVID_CERT) {
                break;
            }
        }

        // Check if the downloaded cert matches.
        let path = "/tmp/caliptra_ldevid_cert.der";
        assert!(Path::new(path).exists());
        let mut ldevid_cert_buffer = Vec::new();
        let mut idevid_csr_file = File::open(path).unwrap();
        idevid_csr_file
            .read_to_end(&mut ldevid_cert_buffer)
            .unwrap();
        assert_eq!(data, ldevid_cert_buffer[..]);
    }

    #[test]
    fn test_tb_services_cb() {
        let output = Rc::new(RefCell::new(vec![]));
        let output2 = output.clone();

        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mailbox = Mailbox::new(mailbox_ram);
        let args = CaliptraRootBusArgs {
            tb_services_cb: TbServicesCb::new(move |ch| output2.borrow_mut().push(ch)),
            ..Default::default()
        };
        let mut soc_reg: SocRegisters = SocRegisters::new(&clock, mailbox, Iccm::new(), args);

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, b'h'.into());

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, b'i'.into());

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, 0xff);

        assert_eq!(&*output.borrow(), &vec![b'h', b'i', 0xff]);
    }
}
