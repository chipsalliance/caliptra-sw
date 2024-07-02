/*++

Licensed under the Apache-2.0 license.

File Name:

    soc_reg.rs

Abstract:

    File contains SOC Register implementation

--*/

use crate::helpers::{bytes_from_words_be, words_from_bytes_be};
use crate::root_bus::ReadyForFwCbArgs;
use crate::{CaliptraRootBusArgs, Iccm, MailboxInternal};
use caliptra_emu_bus::BusError::{LoadAccessFault, StoreAccessFault};
use caliptra_emu_bus::{
    ActionHandle, Bus, BusError, Clock, ReadOnlyRegister, ReadWriteRegister, Register, Timer,
    TimerAction,
};
use caliptra_emu_cpu::{IntSource, Irq, Pic};
use caliptra_emu_derive::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::EtrngResponse;
use caliptra_registers::soc_ifc::regs::CptraHwConfigReadVal;
use caliptra_registers::soc_ifc_trng::regs::{CptraTrngStatusReadVal, CptraTrngStatusWriteVal};
use std::cell::RefCell;
use std::rc::Rc;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::InMemoryRegister;

// Second parameter is schedule(ticks_from_now: u64, cb: Box<dyn FnOnce(&mut
// Mailbox)>), which is called to schedule firmware writing in the future
type ReadyForFwCallback = Box<dyn FnMut(ReadyForFwCbArgs)>;
type UploadUpdateFwCallback = Box<dyn FnMut(&mut MailboxInternal)>;
type BootFsmGoCallback = Box<dyn FnMut()>;
type DownloadIdevidCsrCallback =
    Box<dyn FnMut(&mut MailboxInternal, &mut InMemoryRegister<u32, DebugManufService::Register>)>;

mod constants {
    #![allow(unused)]

    pub const CPTRA_HW_ERROR_FATAL_START: u32 = 0x0;
    pub const CPTRA_HW_ERROR_NON_FATAL_START: u32 = 0x4;
    pub const CPTRA_FW_ERROR_FATAL_START: u32 = 0x8;
    pub const CPTRA_FW_ERROR_NON_FATAL_START: u32 = 0xc;
    pub const CPTRA_HW_ERROR_ENC_START: u32 = 0x10;
    pub const CPTRA_FW_ERROR_ENC_START: u32 = 0x14;
    pub const CPTRA_FW_EXTENDED_ERROR_INFO_START: u32 = 0x18;
    pub const CPTRA_FW_EXTENDED_ERROR_INFO_SIZE: usize = 32;
    pub const CPTRA_BOOT_STATUS_START: u32 = 0x38;
    pub const CPTRA_FLOW_STATUS_START: u32 = 0x3c;
    pub const CPTRA_RESET_REASON_START: u32 = 0x40;
    pub const CPTRA_SECURITY_STATE_START: u32 = 0x44;
    pub const CPTRA_MBOX_VALID_PAUSER_START: u32 = 0x48;
    pub const CPTRA_MBOX_VALID_PAUSER_SIZE: usize = 20;
    pub const CPTRA_MBOX_PAUSER_LOCK_START: u32 = 0x5c;
    pub const CPTRA_MBOX_PAUSER_LOCK_SIZE: usize = 20;
    pub const CPTRA_TRNG_VALID_PAUSER_START: u32 = 0x70;
    pub const CPTRA_TRNG_PAUSER_LOCK_START: u32 = 0x74;
    pub const CPTRA_TRNG_DATA_START: u32 = 0x78;
    pub const CPTRA_TRNG_DATA_SIZE: usize = 48;
    pub const CPTRA_TRNG_CTRL_START: u32 = 0xa8;
    pub const CPTRA_TRNG_STATUS_START: u32 = 0xac;
    pub const CPTRA_FUSE_WR_DONE_START: u32 = 0xb0;
    pub const CPTRA_TIMER_CONFIG_START: u32 = 0xb4;
    pub const CPTRA_BOOTFSM_GO_START: u32 = 0xb8;
    pub const CPTRA_DBG_MANUF_SERVICE_REG_START: u32 = 0xbc;
    pub const CPTRA_CLK_GATING_EN_START: u32 = 0xc0;
    pub const CPTRA_GENERIC_INPUT_WIRES_START: u32 = 0xc4;
    pub const CPTRA_GENERIC_INPUT_WIRES_SIZE: usize = 8;
    pub const CPTRA_GENERIC_OUTPUT_WIRES_START: u32 = 0xcc;
    pub const CPTRA_GENERIC_OUTPUT_WIRES_SIZE: usize = 8;
    pub const FUSE_UDS_SEED_SIZE: usize = 48;
    pub const FUSE_FIELD_ENTROPY_SIZE: usize = 32;
    pub const CPTRA_WDT_TIMER1_EN_START: u32 = 0xe4;
    pub const CPTRA_WDT_TIMER1_CTRL_START: u32 = 0xe8;
    pub const CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START: u32 = 0xec;
    pub const CPTRA_WDT_TIMER2_EN_START: u32 = 0xf4;
    pub const CPTRA_WDT_TIMER2_CTRL_START: u32 = 0xf8;
    pub const CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START: u32 = 0xfc;
    pub const CPTRA_WDT_STATUS_START: u32 = 0x104;
    pub const CPTRA_FUSE_VALID_PAUSER_START: u32 = 0x108;
    pub const CPTRA_FUSE_PAUSER_LOCK_START: u32 = 0x10c;
    pub const FUSE_VENDOR_PK_HASH_START: u32 = 0x250;
    pub const FUSE_VENDOR_PK_HASH_SIZE: usize = 48;
    pub const FUSE_VENDOR_PK_MASK_START: u32 = 0x280;
    pub const FUSE_OWNER_PK_HASH_START: u32 = 0x284;
    pub const FUSE_OWNER_PK_HASH_SIZE: usize = 48;
    pub const FUSE_FMC_SVN_START: u32 = 0x2b4;
    pub const FUSE_RUNTIME_SVN_START: u32 = 0x2b8;
    pub const FUSE_RUNTIME_SVN_SIZE: usize = 16;
    pub const FUSE_ANTI_ROLLBACK_DISABLE_START: u32 = 0x2c8;
    pub const FUSE_IDEVID_CERT_ATTR_START: u32 = 0x2cc;
    pub const FUSE_IDEVID_CERT_ATTR_SIZE: usize = 96;
    pub const FUSE_IDEVID_MANUF_HSM_ID_START: u32 = 0x32c;
    pub const FUSE_IDEVID_MANUF_HSM_ID_SIZE: usize = 16;
    pub const FUSE_LIFE_CYCLE_START: u32 = 0x33c;
    pub const INTERNAL_OBF_KEY_SIZE: usize = 32;
    pub const INTERNAL_ICCM_LOCK_START: u32 = 0x620;
    pub const INTERNAL_FW_UPDATE_RESET_START: u32 = 0x624;
    pub const INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES_START: u32 = 0x628;
    pub const INTERNAL_NMI_VECTOR_START: u32 = 0x62c;
}
use constants::*;

register_bitfields! [
    u32,

    /// Flow Status
    FlowStatus [
        STATUS OFFSET(0) NUMBITS(23) [],
        LDEVID_CERT_READY OFFSET(23) NUMBITS(1) [],
        IDEVID_CSR_READY OFFSET(24) NUMBITS(1) [],
        BOOT_FSM_PS OFFSET(25) NUMBITS(3) [],
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
    pub DebugManufService [
        REQ_IDEVID_CSR OFFSET(0) NUMBITS(1) [],
        REQ_LDEVID_CERT OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// Reset Reason
    ResetReason [
        FW_UPD_RESET OFFSET(0) NUMBITS(1) [],
        WARM_RESET OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// WDT Enable
    WdtEnable [
        TIMER_EN OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// WDT Control
    WdtControl [
        TIMER_RESTART OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// WDT Status
    WdtStatus [
        T1_TIMEOUT OFFSET(0) NUMBITS(1) [],
        T2_TIMEOUT OFFSET(1) NUMBITS(1) [],
        RSVD OFFSET(2) NUMBITS(30) [],
    ],

    /// LMS Verify
    LmsVerify [
        LMS_VERIFY OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// SoC Stepping ID
    SocSteppingId [
        SOC_STEPPING_ID OFFSET(0) NUMBITS(16) [],
        RSVD OFFSET(16) NUMBITS(16) [],
    ],

    /// Per-Type Interrupt Enable Register
    GlobalIntrEn [
        ERROR_EN OFFSET(0) NUMBITS(1) [],
        NOTIF_EN OFFSET(1) NUMBITS(1) [],
    ],

    /// Per-Event Interrupt Enable Register
    ErrorIntrEn [
        ERROR_INTERNAL_EN OFFSET(0) NUMBITS(1) [],
        ERROR_INV_DEV_EN OFFSET(1) NUMBITS(1) [],
        ERROR_CMD_FAIL_EN OFFSET(2) NUMBITS(1) [],
        ERROR_BAD_FUSE_EN OFFSET(3) NUMBITS(1) [],
        ERROR_ICCM_BLOCKED_EN OFFSET(4) NUMBITS(1) [],
        ERROR_MBOX_ECC_UNC_EN OFFSET(5) NUMBITS(1) [],
        ERROR_WDT_TIMER1_TIMEOUT_EN OFFSET(6) NUMBITS(1) [],
        ERROR_WDT_TIMER2_TIMEOUT_EN OFFSET(7) NUMBITS(1) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],

    /// Per-Event Interrupt Enable Register
    NotifIntrEn [
        NOTIF_CMD_AVAIL_EN OFFSET(0) NUMBITS(1) [],
        NOTIF_MBOX_ECC_COR_EN OFFSET(1) NUMBITS(1) [],
        NOTIF_DEBUG_LOCKED_EN OFFSET(2) NUMBITS(1) [],
        NOTIF_SCAN_MODE_EN OFFSET(3) NUMBITS(1) [],
        NOTIF_SOC_REQ_LOCK_EN OFFSET(4) NUMBITS(1) [],
        NOTIF_GEN_IN_TOGGLE_EN OFFSET(5) NUMBITS(1) [],
        RSVD OFFSET(6) NUMBITS(26) [],
    ],

    /// Interrupt Status Aggregation Register
    ErrorGlobalIntr [
        AGG_STS OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// Interrupt Status Aggregation Register
    NotifGlobalIntr [
        AGG_STS OFFSET(0) NUMBITS(1) [],
        RSVD OFFSET(1) NUMBITS(31) [],
    ],

    /// ErrorIntrT
    ErrorIntrT [
        ERROR_INTERNAL_STS OFFSET(0) NUMBITS(1) [],
        ERROR_INV_DEV_STS OFFSET(1) NUMBITS(1) [],
        ERROR_CMD_FAIL_STS OFFSET(2) NUMBITS(1) [],
        ERROR_BAD_FUSE_STS OFFSET(3) NUMBITS(1) [],
        ERROR_ICCM_BLOCKED_STS OFFSET(4) NUMBITS(1) [],
        ERROR_MBOX_ECC_UNC_STS OFFSET(5) NUMBITS(1) [],
        ERROR_WDT_TIMER1_TIMEOUT_STS OFFSET(6) NUMBITS(1) [],
        ERROR_WDT_TIMER2_TIMEOUT_STS OFFSET(7) NUMBITS(1) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],

    /// NotifIntrT
    NotifIntrT [
        NOTIF_CMD_AVAIL_STS OFFSET(0) NUMBITS(1) [],
        NOTIF_MBOX_ECC_COR_STS OFFSET(1) NUMBITS(1) [],
        NOTIF_DEBUG_LOCKED_STS OFFSET(2) NUMBITS(1) [],
        NOTIF_SCAN_MODE_STS OFFSET(3) NUMBITS(1) [],
        NOTIF_SOC_REQ_LOCK_STS OFFSET(4) NUMBITS(1) [],
        NOTIF_GEN_IN_TOGGLE_STS OFFSET(5) NUMBITS(1) [],
        RSVD OFFSET(6) NUMBITS(26) [],
    ],

    /// Interrupt Trigger Register
    ErrIntrTrigT [
        ERROR_INTERNAL_TRIG OFFSET(0) NUMBITS(1) [],
        ERROR_INV_DEV_TRIG OFFSET(1) NUMBITS(1) [],
        ERROR_CMD_FAIL_TRIG OFFSET(2) NUMBITS(1) [],
        ERROR_BAD_FUSE_TRIG OFFSET(3) NUMBITS(1) [],
        ERROR_ICCM_BLOCKED_TRIG OFFSET(4) NUMBITS(1) [],
        ERROR_MBOX_ECC_UNC_TRIG OFFSET(5) NUMBITS(1) [],
        ERROR_WDT_TIMER1_TIMEOUT_TRIG OFFSET(6) NUMBITS(1) [],
        ERROR_WDT_TIMER2_TIMEOUT_TRIG OFFSET(7) NUMBITS(1) [],
        RSVD OFFSET(8) NUMBITS(24) [],
    ],

    /// Interrupt Trigger Register
    NotifIntrTrigT [
        NOTIF_CMD_AVAIL_TRIG OFFSET(0) NUMBITS(1) [],
        NOTIF_MBOX_ECC_COR_TRIG OFFSET(1) NUMBITS(1) [],
        NOTIF_DEBUG_LOCKED_TRIG OFFSET(2) NUMBITS(1) [],
        NOTIF_SCAN_MODE_TRIG OFFSET(3) NUMBITS(1) [],
        NOTIF_SOC_REQ_LOCK_TRIG OFFSET(4) NUMBITS(1) [],
        NOTIF_GEN_IN_TOGGLE_TRIG OFFSET(5) NUMBITS(1) [],
        RSVD OFFSET(6) NUMBITS(26) [],
    ],
];

/// SOC Register peripheral
#[derive(Clone)]
pub struct SocRegistersInternal {
    regs: Rc<RefCell<SocRegistersImpl>>,
}

/// Caliptra Register Start Address
const CALIPTRA_REG_START_ADDR: u32 = 0x00;

/// Caliptra Register End Address
const CALIPTRA_REG_END_ADDR: u32 = 0x820;

/// Caliptra Fuse start address
const FUSE_START_ADDR: u32 = 0x200;
/// Caliptra Fuse end address
const FUSE_END_ADDR: u32 = 0x340;

impl SocRegistersInternal {
    /// Create an instance of SOC register peripheral
    pub fn new(
        clock: &Clock,
        mailbox: MailboxInternal,
        iccm: Iccm,
        pic: &Pic,
        args: CaliptraRootBusArgs,
    ) -> Self {
        Self {
            regs: Rc::new(RefCell::new(SocRegistersImpl::new(
                clock, mailbox, iccm, pic, args,
            ))),
        }
    }
    pub fn is_debug_locked(&self) -> bool {
        let reg = &self.regs.borrow().cptra_security_state.reg;
        reg.read(SecurityState::DEBUG_LOCKED) != 0
    }

    /// Get Unique device secret
    pub fn uds(&self) -> [u8; FUSE_UDS_SEED_SIZE] {
        if self.is_debug_locked() {
            bytes_from_words_be(&self.regs.borrow().fuse_uds_seed)
        } else {
            [0xff_u8; FUSE_UDS_SEED_SIZE]
        }
    }

    // Get field entropy
    pub fn field_entropy(&self) -> [u8; FUSE_FIELD_ENTROPY_SIZE] {
        if self.is_debug_locked() {
            bytes_from_words_be(&self.regs.borrow().fuse_field_entropy)
        } else {
            [0xff_u8; FUSE_FIELD_ENTROPY_SIZE]
        }
    }

    /// Get deobfuscation engine key
    pub fn doe_key(&self) -> [u8; INTERNAL_OBF_KEY_SIZE] {
        if self.is_debug_locked() {
            bytes_from_words_be(&self.regs.borrow().internal_obf_key)
        } else {
            [0xff_u8; INTERNAL_OBF_KEY_SIZE]
        }
    }

    /// Clear secrets
    pub fn clear_secrets(&mut self) {
        self.regs.borrow_mut().clear_secrets();
    }

    pub fn set_hw_config(&mut self, val: CptraHwConfigReadVal) {
        self.regs.borrow_mut().cptra_hw_config = val.into();
    }

    pub fn external_regs(&self) -> SocRegistersExternal {
        SocRegistersExternal {
            regs: self.regs.clone(),
        }
    }
}

impl Bus for SocRegistersInternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            CALIPTRA_REG_START_ADDR..=CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().read(size, addr)
            }
            _ => Err(LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            FUSE_START_ADDR..=FUSE_END_ADDR => {
                // Microcontroller can't ever write to fuse registers
                Err(StoreAccessFault)
            }
            CALIPTRA_REG_START_ADDR..=CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().write(size, addr, val)
            }
            _ => Err(StoreAccessFault),
        }
    }

    fn poll(&mut self) {
        self.regs.borrow_mut().poll();

        let mut regs = self.regs.borrow_mut();
        if regs.mailbox.get_notif_irq() {
            regs.notif_internal_intr_r
                .reg
                .modify(NotifIntrT::NOTIF_CMD_AVAIL_STS.val(1));
            regs.notif_global_intr_r
                .reg
                .modify(NotifGlobalIntr::AGG_STS.val(1));
        }

        if regs.global_intr_en_r.reg.is_set(GlobalIntrEn::ERROR_EN)
            && regs.error_intr_en_r.reg.get() & regs.error_internal_intr_r.reg.get() != 0
        {
            regs.err_irq.set_level(true);
        }
        if regs.global_intr_en_r.reg.is_set(GlobalIntrEn::NOTIF_EN)
            && regs.notif_intr_en_r.reg.get() & regs.notif_internal_intr_r.reg.get() != 0
        {
            regs.notif_irq.set_level(true);
        }
    }

    fn warm_reset(&mut self) {
        self.regs.borrow_mut().bus_warm_reset();
    }

    fn update_reset(&mut self) {
        self.regs.borrow_mut().bus_update_reset();
    }
}

pub struct SocRegistersExternal {
    regs: Rc<RefCell<SocRegistersImpl>>,
}
impl Bus for SocRegistersExternal {
    /// Read data of specified size from given address
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        match addr {
            CALIPTRA_REG_START_ADDR..=CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().read(size, addr)
            }
            _ => Err(LoadAccessFault),
        }
    }

    /// Write data of specified size to given address
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        match addr {
            FUSE_START_ADDR..=FUSE_END_ADDR => {
                if self.regs.borrow_mut().fuses_can_be_written {
                    self.regs.borrow_mut().write(size, addr, val)
                } else {
                    Err(StoreAccessFault)
                }
            }
            CALIPTRA_REG_START_ADDR..=CALIPTRA_REG_END_ADDR => {
                self.regs.borrow_mut().write(size, addr, val)
            }
            _ => Err(StoreAccessFault),
        }
    }

    fn poll(&mut self) {
        // Do nothing; external interface can't control time
    }

    fn warm_reset(&mut self) {
        // Do nothing; external interface can't control reset
    }

    fn update_reset(&mut self) {
        // Do nothing; external interface can't control reset
    }
}

/// SOC Register implementation

#[derive(Bus)]
#[poll_fn(bus_poll)]
struct SocRegistersImpl {
    #[register(offset = 0x0000)]
    cptra_hw_error_fatal: ReadWriteRegister<u32>,

    #[register(offset = 0x0004)]
    cptra_hw_error_non_fatal: ReadWriteRegister<u32>,

    #[register(offset = 0x0008)]
    cptra_fw_error_fatal: ReadWriteRegister<u32>,

    #[register(offset = 0x000c)]
    cptra_fw_error_non_fatal: ReadWriteRegister<u32>,

    #[register(offset = 0x0010)]
    cptra_hw_error_enc: ReadWriteRegister<u32>,

    #[register(offset = 0x0014)]
    cptra_fw_error_enc: ReadWriteRegister<u32>,

    #[register_array(offset = 0x0018)]
    cptra_fw_extended_error_info: [u32; CPTRA_FW_EXTENDED_ERROR_INFO_SIZE / 4],

    #[register(offset = 0x0038)]
    cptra_boot_status: ReadWriteRegister<u32>,

    #[register(offset = 0x003c, write_fn = on_write_flow_status)]
    cptra_flow_status: ReadWriteRegister<u32, FlowStatus::Register>,

    #[register(offset = 0x0040)]
    cptra_reset_reason: ReadOnlyRegister<u32, ResetReason::Register>,

    #[register(offset = 0x0044)]
    cptra_security_state: ReadOnlyRegister<u32, SecurityState::Register>,

    // TODO: Functionality for mbox pauser regs needs to be implemented
    #[register_array(offset = 0x0048)]
    cptra_mbox_valid_pauser: [u32; CPTRA_MBOX_VALID_PAUSER_SIZE / 4],

    #[register_array(offset = 0x005c)]
    cptra_mbox_pauser_lock: [u32; CPTRA_MBOX_PAUSER_LOCK_SIZE / 4],

    #[register(offset = 0x0070)]
    cptra_trng_valid_pauser: ReadWriteRegister<u32>,

    #[register(offset = 0x0074)]
    cptra_trng_pauser_lock: ReadWriteRegister<u32>,

    #[register_array(offset = 0x0078)]
    cptra_trng_data: [u32; CPTRA_TRNG_DATA_SIZE / 4],

    #[register(offset = 0x00a8, write_fn = on_write_trng_status)]
    cptra_trng_ctrl: u32,

    #[register(offset = 0x00ac, write_fn = on_write_trng_status)]
    cptra_trng_status: u32,

    #[register(offset = 0x00b0, write_fn = on_write_fuse_wr_done)]
    cptra_fuse_wr_done: u32,

    #[register(offset = 0x00b4)]
    cptra_timer_config: ReadWriteRegister<u32>,

    #[register(offset = 0x00b8, write_fn = on_write_bootfsm_go)]
    cptra_bootfsm_go: u32,

    #[register(offset = 0x00bc)]
    cptra_dbg_manuf_service_reg: ReadWriteRegister<u32, DebugManufService::Register>,

    #[register(offset = 0x00c0)]
    cptra_clk_gating_en: ReadOnlyRegister<u32>,

    #[register_array(offset = 0x00c4)]
    cptra_generic_input_wires: [u32; CPTRA_GENERIC_INPUT_WIRES_SIZE / 4],

    #[register_array(offset = 0x00cc, write_fn = on_write_generic_output_wires)]
    cptra_generic_output_wires: [u32; CPTRA_GENERIC_OUTPUT_WIRES_SIZE / 4],

    #[register(offset = 0x00d4)]
    cptra_hw_rev_id: ReadOnlyRegister<u32>,

    #[register_array(offset = 0x00d8)]
    cptra_fw_rev_id: [u32; 2],

    #[register(offset = 0x00e0, write_fn = write_disabled)]
    cptra_hw_config: u32,

    #[register(offset = 0x00e4, write_fn = on_write_wdt_timer1_en)]
    cptra_wdt_timer1_en: ReadWriteRegister<u32, WdtEnable::Register>,

    #[register(offset = 0x00e8, write_fn = on_write_wdt_timer1_ctrl)]
    cptra_wdt_timer1_ctrl: ReadWriteRegister<u32, WdtControl::Register>,

    #[register_array(offset = 0x00ec)]
    cptra_wdt_timer1_timeout_period: [u32; 2],

    #[register(offset = 0x00f4, write_fn = on_write_wdt_timer2_en)]
    cptra_wdt_timer2_en: ReadWriteRegister<u32, WdtEnable::Register>,

    #[register(offset = 0x00f8, write_fn = on_write_wdt_timer2_ctrl)]
    cptra_wdt_timer2_ctrl: ReadWriteRegister<u32, WdtControl::Register>,

    #[register_array(offset = 0x00fc)]
    cptra_wdt_timer2_timeout_period: [u32; 2],

    #[register(offset = 0x0104)]
    cptra_wdt_status: ReadOnlyRegister<u32, WdtStatus::Register>,

    // TODO: Functionality for fuse pauser regs needs to be implemented
    #[register(offset = 0x0108)]
    cptra_fuse_valid_pauser: ReadWriteRegister<u32>,

    #[register(offset = 0x010c)]
    cptra_fuse_pauser_lock: ReadWriteRegister<u32>,

    #[register(offset = 0x0118)]
    cptra_i_trng_entropy_config_0: u32,

    #[register(offset = 0x011c)]
    cptra_i_trng_entropy_config_1: u32,

    #[register_array(offset = 0x0120)]
    cptra_rsvd_reg: [u32; 2],

    #[register_array(offset = 0x0200)]
    fuse_uds_seed: [u32; FUSE_UDS_SEED_SIZE / 4],

    #[register_array(offset = 0x110)]
    cptra_wdt_cfg: [u32; 2],

    #[register_array(offset = 0x0230)]
    fuse_field_entropy: [u32; FUSE_FIELD_ENTROPY_SIZE / 4],

    #[register_array(offset = 0x0250)]
    fuse_vendor_pk_hash: [u32; FUSE_VENDOR_PK_HASH_SIZE / 4],

    #[register(offset = 0x0280)]
    fuse_vendor_pk_hash_mask: ReadWriteRegister<u32, VendorPubKeyMask::Register>,

    #[register_array(offset = 0x0284)]
    fuse_owner_pk_hash: [u32; FUSE_OWNER_PK_HASH_SIZE / 4],

    #[register(offset = 0x02b4)]
    fuse_fmc_svn: u32,

    #[register_array(offset = 0x02b8)]
    fuse_runtime_svn: [u32; FUSE_RUNTIME_SVN_SIZE / 4],

    #[register(offset = 0x02c8)]
    fuse_anti_rollback_disable: u32,

    #[register_array(offset = 0x02cc)]
    fuse_idevid_cert_attr: [u32; FUSE_IDEVID_CERT_ATTR_SIZE / 4],

    #[register_array(offset = 0x032c)]
    fuse_idevid_manuf_hsm_id: [u32; FUSE_IDEVID_MANUF_HSM_ID_SIZE / 4],

    #[register(offset = 0x033c)]
    fuse_life_cycle: u32,

    #[register(offset = 0x340)]
    fuse_lms_verify: ReadWriteRegister<u32, LmsVerify::Register>,

    #[register(offset = 0x344)]
    fuse_lms_revocation: u32,

    #[register(offset = 0x348)]
    fuse_soc_stepping_id: ReadWriteRegister<u32, SocSteppingId::Register>,

    /// INTERNAL_OBF_KEY Register
    internal_obf_key: [u32; 8],

    /// INTERNAL_ICCM_LOCK Register
    #[register(offset = 0x0620, write_fn = on_write_iccm_lock)]
    internal_iccm_lock: ReadWriteRegister<u32, IccmLock::Register>,

    /// INTERNAL_FW_UPDATE_RESET Register
    #[register(offset = 0x0624, write_fn = on_write_internal_fw_update_reset)]
    internal_fw_update_reset: ReadWriteRegister<u32, FwUpdateReset::Register>,

    /// INTERNAL_FW_UPDATE_RESET_WAIT_CYCLES Register
    #[register(offset = 0x0628)]
    internal_fw_update_reset_wait_cycles: ReadWriteRegister<u32, FwUpdateResetWaitCycles::Register>,

    /// INTERNAL_NMI_VECTOR Register
    #[register(offset = 0x062c, write_fn = on_write_internal_nmi_vector)]
    internal_nmi_vector: ReadWriteRegister<u32>,

    /// GLOBAL_INTR_EN_R Register
    #[register(offset = 0x0800)]
    global_intr_en_r: ReadWriteRegister<u32, GlobalIntrEn::Register>,

    /// ERROR_INTR_EN_R Register
    #[register(offset = 0x0804)]
    error_intr_en_r: ReadWriteRegister<u32, ErrorIntrEn::Register>,

    /// NOTIF_INTR_EN_R Register
    #[register(offset = 0x0808)]
    notif_intr_en_r: ReadWriteRegister<u32, NotifIntrEn::Register>,

    /// ERROR_GLOBAL_INTR_R Register
    #[register(offset = 0x080c)]
    error_global_intr_r: ReadWriteRegister<u32, ErrorGlobalIntr::Register>,

    /// NOTIF_GLOBAL_INTR_R Register
    #[register(offset = 0x0810)]
    notif_global_intr_r: ReadWriteRegister<u32, NotifGlobalIntr::Register>,

    /// ERROR_INTERNAL_INTR_R Register
    #[register(offset = 0x0814)]
    error_internal_intr_r: ReadWriteRegister<u32, ErrorIntrT::Register>,

    /// NOTIF_INTERNAL_INTR_R Register
    #[register(offset = 0x818, write_fn = on_write_notif_internal_intr)]
    notif_internal_intr_r: ReadWriteRegister<u32, NotifIntrT::Register>,

    /// ERROR_INTR_TRIG Register
    #[register(offset = 0x81c)]
    error_intr_trig_r: ReadWriteRegister<u32, ErrIntrTrigT::Register>,

    /// NOTIF_INTR_TRIG Register
    #[register(offset = 0x820, write_fn = on_write_notif_intr_trig)]
    notif_intr_trig_r: ReadWriteRegister<u32, NotifIntrTrigT::Register>,

    /// Mailbox
    mailbox: MailboxInternal,

    /// ICCM
    iccm: Iccm,

    /// Timer
    timer: Timer,

    err_irq: Irq,

    notif_irq: Irq,

    /// Firmware Write Complete action
    op_fw_write_complete_action: Option<ActionHandle>,
    #[allow(clippy::type_complexity)]
    op_fw_write_complete_cb: Option<Box<dyn FnOnce(&mut MailboxInternal)>>,

    /// Firmware Read Complete action
    op_fw_read_complete_action: Option<ActionHandle>,

    /// IDEVID CSR Read Complete action
    op_idevid_csr_read_complete_action: Option<ActionHandle>,

    /// Reset Trigger action
    op_reset_trigger_action: Option<ActionHandle>,

    /// test bench services callback
    tb_services_cb: Box<dyn FnMut(u8)>,

    ready_for_fw_cb: ReadyForFwCallback,

    upload_update_fw: UploadUpdateFwCallback,

    bootfsm_go_cb: BootFsmGoCallback,

    fuses_can_be_written: bool,

    download_idevid_csr_cb: DownloadIdevidCsrCallback,

    /// WDT Timer1 Expired action
    op_wdt_timer1_expired_action: Option<ActionHandle>,

    /// WDT Timer2 Expired action
    op_wdt_timer2_expired_action: Option<ActionHandle>,

    etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
    pending_etrng_response: Option<EtrngResponse>,
    op_pending_etrng_response_action: Option<ActionHandle>,
}

impl SocRegistersImpl {
    /// Default unique device secret
    const UDS: [u8; FUSE_UDS_SEED_SIZE] = [
        0xF5, 0x8C, 0x4C, 0x4, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F, 0x7B, 0xFB,
        0xD6, 0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F, 0x77, 0x7B, 0xC6, 0x70,
        0x2C, 0x7D, 0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA, 0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x4,
        0x23, 0x14, 0x61,
    ];

    /// The number of CPU clock cycles it takes to read the firmware from the mailbox.
    const FW_READ_TICKS: u64 = 0;

    /// The number of CPU clock cycles it takes to read the IDEVID CSR from the mailbox.
    const IDEVID_CSR_READ_TICKS: u64 = 100;

    pub fn new(
        clock: &Clock,
        mailbox: MailboxInternal,
        iccm: Iccm,
        pic: &Pic,
        mut args: CaliptraRootBusArgs,
    ) -> Self {
        let flow_status = InMemoryRegister::<u32, FlowStatus::Register>::new(0);
        flow_status.write(FlowStatus::READY_FOR_FUSES.val(1));

        let regs = Self {
            cptra_hw_error_fatal: ReadWriteRegister::new(0),
            cptra_hw_error_non_fatal: ReadWriteRegister::new(0),
            cptra_fw_error_fatal: ReadWriteRegister::new(0),
            cptra_fw_error_non_fatal: ReadWriteRegister::new(0),
            cptra_hw_error_enc: ReadWriteRegister::new(0),
            cptra_fw_error_enc: ReadWriteRegister::new(0),
            cptra_fw_extended_error_info: Default::default(),
            cptra_boot_status: ReadWriteRegister::new(0),
            cptra_flow_status: ReadWriteRegister::new(flow_status.get()),
            cptra_reset_reason: ReadOnlyRegister::new(0),
            cptra_security_state: ReadOnlyRegister::new(args.security_state.into()),
            cptra_mbox_valid_pauser: Default::default(),
            cptra_mbox_pauser_lock: Default::default(),
            cptra_trng_valid_pauser: ReadWriteRegister::new(0),
            cptra_trng_pauser_lock: ReadWriteRegister::new(0),
            cptra_trng_data: Default::default(),
            cptra_trng_ctrl: 0,
            cptra_trng_status: 0,
            cptra_fuse_wr_done: 0,
            cptra_timer_config: ReadWriteRegister::new(0),
            cptra_bootfsm_go: 0,
            cptra_dbg_manuf_service_reg: ReadWriteRegister::new(0),
            cptra_clk_gating_en: ReadOnlyRegister::new(0),
            cptra_generic_input_wires: Default::default(),
            cptra_generic_output_wires: Default::default(),
            cptra_hw_rev_id: ReadOnlyRegister::new(if cfg!(feature = "hw-1.0") {
                0x1
            } else {
                0x11
            }),
            cptra_fw_rev_id: Default::default(),
            cptra_hw_config: 0,
            fuse_uds_seed: words_from_bytes_be(&Self::UDS),
            fuse_field_entropy: [0xffff_ffff; 8],
            fuse_vendor_pk_hash: Default::default(),
            fuse_vendor_pk_hash_mask: ReadWriteRegister::new(0),
            fuse_owner_pk_hash: Default::default(),
            fuse_fmc_svn: Default::default(),
            fuse_runtime_svn: Default::default(),
            fuse_anti_rollback_disable: Default::default(),
            fuse_idevid_cert_attr: Default::default(),
            fuse_idevid_manuf_hsm_id: Default::default(),
            fuse_life_cycle: Default::default(),
            fuse_lms_verify: ReadWriteRegister::new(0),
            fuse_lms_revocation: Default::default(),
            fuse_soc_stepping_id: ReadWriteRegister::new(0),
            internal_obf_key: args.cptra_obf_key,
            internal_iccm_lock: ReadWriteRegister::new(0),
            internal_fw_update_reset: ReadWriteRegister::new(0),
            internal_fw_update_reset_wait_cycles: ReadWriteRegister::new(5),
            internal_nmi_vector: ReadWriteRegister::new(0),
            global_intr_en_r: ReadWriteRegister::new(0),
            error_intr_en_r: ReadWriteRegister::new(0),
            notif_intr_en_r: ReadWriteRegister::new(0),
            error_global_intr_r: ReadWriteRegister::new(0),
            notif_global_intr_r: ReadWriteRegister::new(0),
            error_internal_intr_r: ReadWriteRegister::new(0),
            notif_internal_intr_r: ReadWriteRegister::new(1),
            error_intr_trig_r: ReadWriteRegister::new(0),
            notif_intr_trig_r: ReadWriteRegister::new(0),
            mailbox,
            iccm,
            timer: Timer::new(clock),
            err_irq: pic.register_irq(IntSource::SocIfcErr.into()),
            notif_irq: pic.register_irq(IntSource::SocIfcNotif.into()),
            op_fw_write_complete_action: None,
            op_fw_write_complete_cb: None,
            op_fw_read_complete_action: None,
            op_idevid_csr_read_complete_action: None,
            op_reset_trigger_action: None,
            tb_services_cb: args.tb_services_cb.take(),
            ready_for_fw_cb: args.ready_for_fw_cb.take(),
            upload_update_fw: args.upload_update_fw.take(),
            fuses_can_be_written: true,
            bootfsm_go_cb: args.bootfsm_go_cb.take(),
            download_idevid_csr_cb: args.download_idevid_csr_cb.take(),
            cptra_wdt_timer1_en: ReadWriteRegister::new(0),
            cptra_wdt_timer1_ctrl: ReadWriteRegister::new(0),
            cptra_wdt_timer1_timeout_period: [0xffff_ffff; 2],
            cptra_wdt_timer2_en: ReadWriteRegister::new(0),
            cptra_wdt_timer2_ctrl: ReadWriteRegister::new(0),
            cptra_wdt_timer2_timeout_period: [0xffff_ffff; 2],
            cptra_wdt_status: ReadOnlyRegister::new(0),
            cptra_i_trng_entropy_config_0: 0,
            cptra_i_trng_entropy_config_1: 0,
            cptra_rsvd_reg: Default::default(),
            op_wdt_timer1_expired_action: None,
            op_wdt_timer2_expired_action: None,
            etrng_responses: args.etrng_responses,
            pending_etrng_response: None,
            op_pending_etrng_response_action: None,
            cptra_wdt_cfg: [0x0; 2],
            cptra_fuse_valid_pauser: ReadWriteRegister::new(0xffff_ffff),
            cptra_fuse_pauser_lock: ReadWriteRegister::new(0),
        };

        regs
    }

    /// Clear secrets
    fn clear_secrets(&mut self) {
        self.fuse_uds_seed = [0u32; 12];
        self.fuse_field_entropy = [0u32; 8];
        self.internal_obf_key = [0u32; 8];
    }

    fn write_disabled(&mut self, _size: RvSize, _val: RvData) -> Result<(), BusError> {
        Err(BusError::StoreAccessFault)
    }

    fn on_write_bootfsm_go(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if (val & 1) != (self.cptra_bootfsm_go & 1) && (val & 1) != 0 {
            self.cptra_bootfsm_go = 1;
            (self.bootfsm_go_cb)();
        }
        Ok(())
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

    /// On Write callback for initiating warm reset.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the write
    /// * `val` - Data to write
    ///
    /// # Error
    ///
    /// * `BusError` - Exception with cause `BusError::StoreAccessFault` or `BusError::StoreAddrMisaligned`
    fn on_write_warm_reset(&mut self, size: RvSize, _val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            Err(BusError::StoreAccessFault)?
        }

        // [TODO] Enable warm reset after design agreement.
        // // Schedule warm reset timer action.
        // self.op_reset_trigger_action =
        //     Some(self.timer.schedule_reset_in(0, TimerActionType::WarmReset));

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

        // If ready_for_fw bit is set, run the op_fn_write_complete_cb.
        if self.cptra_flow_status.reg.is_set(FlowStatus::READY_FOR_FW) {
            let op_fw_write_complete_action = &mut self.op_fw_write_complete_action;
            let op_fw_write_complete_cb = &mut self.op_fw_write_complete_cb;
            let timer = &self.timer;
            let sched_fn = move |ticks_from_now: u64, cb: Box<dyn FnOnce(&mut MailboxInternal)>| {
                *op_fw_write_complete_action = Some(timer.schedule_poll_in(ticks_from_now));
                *op_fw_write_complete_cb = Some(cb);
            };
            let args = ReadyForFwCbArgs {
                mailbox: &mut self.mailbox,
                sched_fn: Box::new(sched_fn),
            };
            (self.ready_for_fw_cb)(args);
        } else if self
            .cptra_flow_status
            .reg
            .is_set(FlowStatus::IDEVID_CSR_READY)
        {
            self.op_idevid_csr_read_complete_action =
                Some(self.timer.schedule_poll_in(Self::IDEVID_CSR_READ_TICKS));
        }

        Ok(())
    }

    fn on_write_fuse_wr_done(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        if (val & 1) != 0 {
            self.fuses_can_be_written = false;
            self.cptra_fuse_wr_done |= 1;

            self.cptra_flow_status
                .reg
                .modify(FlowStatus::READY_FOR_FUSES::CLEAR);
        }
        Ok(())
    }

    fn on_write_generic_output_wires(
        &mut self,
        size: RvSize,
        index: usize,
        val: RvData,
    ) -> Result<(), BusError> {
        match index {
            0 => self.on_write_tb_services(size, val),
            1 => self.on_write_warm_reset(size, val),
            _ => Err(StoreAccessFault),
        }
    }

    fn on_write_iccm_lock(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        let iccm_lock_reg = InMemoryRegister::<u32, IccmLock::Register>::new(val);
        if iccm_lock_reg.is_set(IccmLock::LOCK) {
            self.iccm.lock();
        } else {
            self.iccm.unlock();
        }
        self.internal_iccm_lock.write(size, val)
    }

    fn on_write_internal_fw_update_reset(
        &mut self,
        size: RvSize,
        val: RvData,
    ) -> Result<(), BusError> {
        self.internal_fw_update_reset.write(size, val)?;

        // Schedule a firmware update reset timer action.
        self.op_reset_trigger_action =
            Some(self.timer.schedule_action_in(0, TimerAction::UpdateReset));
        Ok(())
    }

    fn on_write_internal_nmi_vector(&mut self, size: RvSize, val: RvData) -> Result<(), BusError> {
        if size != RvSize::Word {
            return Err(BusError::StoreAccessFault);
        }
        self.timer
            .schedule_action_in(0, TimerAction::SetNmiVec { addr: val });
        Ok(())
    }

    fn on_write_wdt_timer1_en(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        self.cptra_wdt_timer1_en.reg.set(val);

        self.cptra_wdt_status
            .reg
            .modify(WdtStatus::T1_TIMEOUT::CLEAR);

        // If timer is enabled, schedule a callback on expiry.
        if self.cptra_wdt_timer1_en.reg.is_set(WdtEnable::TIMER_EN) {
            let timer_period: u64 = (self.cptra_wdt_timer1_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer1_expired_action = None;
        }
        Ok(())
    }

    fn on_write_wdt_timer1_ctrl(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        self.cptra_wdt_timer1_ctrl.reg.set(val);

        if self.cptra_wdt_timer1_en.reg.is_set(WdtEnable::TIMER_EN)
            && self
                .cptra_wdt_timer1_ctrl
                .reg
                .is_set(WdtControl::TIMER_RESTART)
        {
            self.cptra_wdt_status
                .reg
                .modify(WdtStatus::T1_TIMEOUT::CLEAR);

            let timer_period: u64 = (self.cptra_wdt_timer1_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer1_timeout_period[0] as u64;

            self.op_wdt_timer1_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
        Ok(())
    }

    fn on_write_wdt_timer2_en(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        self.cptra_wdt_timer2_en.reg.set(val);

        self.cptra_wdt_status
            .reg
            .modify(WdtStatus::T2_TIMEOUT::CLEAR);

        // If timer is enabled, schedule a callback on expiry.
        if self.cptra_wdt_timer2_en.reg.is_set(WdtEnable::TIMER_EN) {
            let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        } else {
            self.op_wdt_timer2_expired_action = None;
        }
        Ok(())
    }

    fn on_write_wdt_timer2_ctrl(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        self.cptra_wdt_timer2_ctrl.reg.set(val);

        if self.cptra_wdt_timer2_en.reg.is_set(WdtEnable::TIMER_EN)
            && self
                .cptra_wdt_timer2_ctrl
                .reg
                .is_set(WdtControl::TIMER_RESTART)
        {
            self.cptra_wdt_status
                .reg
                .modify(WdtStatus::T2_TIMEOUT::CLEAR);

            let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                | self.cptra_wdt_timer2_timeout_period[0] as u64;

            self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
        }
        Ok(())
    }

    fn on_write_trng_status(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let val = CptraTrngStatusReadVal::from(val);
        if val.data_req() && self.pending_etrng_response.is_none() {
            if let Some(next_response) = self.etrng_responses.next() {
                self.op_pending_etrng_response_action =
                    Some(self.timer.schedule_poll_in(next_response.delay.into()));
                self.pending_etrng_response = Some(next_response);
            }
        }
        self.cptra_trng_status = if !val.data_req() {
            // Clear data_wr_done when data_req is cleared
            CptraTrngStatusWriteVal::from(u32::from(val))
                .data_wr_done(false)
                .into()
        } else {
            val.into()
        };
        Ok(())
    }

    // Clear bits on writing 1
    fn on_write_notif_internal_intr(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        let reg = self.notif_internal_intr_r.reg.get();
        let clear_bits = reg & val;
        self.notif_internal_intr_r.reg.set(reg ^ clear_bits);
        Ok(())
    }

    fn on_write_notif_intr_trig(&mut self, _size: RvSize, val: RvData) -> Result<(), BusError> {
        // Poll the bus to see if we need to trigger an interrupt
        if val != 0 {
            self.notif_internal_intr_r.reg.set(val);
            self.timer.schedule_poll_in(2);
        }
        Ok(())
    }

    fn reset_common(&mut self) {
        // Unlock the ICCM.
        self.iccm.unlock();
    }

    /// Called by Bus::poll() to indicate that time has passed
    fn bus_poll(&mut self) {
        if self.timer.fired(&mut self.op_fw_write_complete_action) {
            if let Some(cb) = self.op_fw_write_complete_cb.take() {
                (cb)(&mut self.mailbox);
                // Schedule a future call to poll() to check on the fw read operation completion.
                self.op_fw_read_complete_action =
                    Some(self.timer.schedule_poll_in(Self::FW_READ_TICKS));
            }
        }

        if self.timer.fired(&mut self.op_fw_read_complete_action) {
            let soc_mbox = self.mailbox.as_external().regs();
            // uC will set status to CMD_COMPLETE after reading the
            // mailbox data; we can't clear the execute bit until that is done.`
            if !soc_mbox.status().read().status().cmd_busy() {
                // Reset the execute bit
                soc_mbox.execute().write(|w| w.execute(false));
            } else {
                self.op_fw_read_complete_action =
                    Some(self.timer.schedule_poll_in(Self::FW_READ_TICKS));
            }
        }

        if self
            .timer
            .fired(&mut self.op_idevid_csr_read_complete_action)
        {
            // Download the Idevid CSR from the mailbox.
            (self.download_idevid_csr_cb)(
                &mut self.mailbox,
                &mut self.cptra_dbg_manuf_service_reg.reg,
            );
        }

        if self.timer.fired(&mut self.op_pending_etrng_response_action) {
            if let Some(etrng_response) = self.pending_etrng_response.take() {
                self.cptra_trng_data = etrng_response.data;
                self.cptra_trng_status = CptraTrngStatusWriteVal::from(self.cptra_trng_status)
                    .data_wr_done(true)
                    .into();
            }
        }

        if self.timer.fired(&mut self.op_wdt_timer1_expired_action) {
            self.cptra_wdt_status.reg.modify(WdtStatus::T1_TIMEOUT::SET);
            self.error_internal_intr_r
                .reg
                .modify(ErrorIntrT::ERROR_WDT_TIMER1_TIMEOUT_STS::SET);

            // If WDT2 is disabled, schedule a callback on it's expiry.
            if !self.cptra_wdt_timer2_en.reg.is_set(WdtEnable::TIMER_EN) {
                self.cptra_wdt_status
                    .reg
                    .modify(WdtStatus::T2_TIMEOUT::CLEAR);
                self.error_internal_intr_r
                    .reg
                    .modify(ErrorIntrT::ERROR_WDT_TIMER2_TIMEOUT_STS::CLEAR);

                let timer_period: u64 = (self.cptra_wdt_timer2_timeout_period[1] as u64) << 32
                    | self.cptra_wdt_timer2_timeout_period[0] as u64;

                self.op_wdt_timer2_expired_action = Some(self.timer.schedule_poll_in(timer_period));
            }
        }

        if self.timer.fired(&mut self.op_wdt_timer2_expired_action) {
            self.cptra_wdt_status.reg.modify(WdtStatus::T2_TIMEOUT::SET);

            // If WDT2 was not scheduled due to WDT1 expiry (i.e WDT2 is disabled), schedule an NMI.
            // Else, do nothing.
            if self.cptra_wdt_timer2_en.reg.is_set(WdtEnable::TIMER_EN) {
                self.error_internal_intr_r
                    .reg
                    .modify(ErrorIntrT::ERROR_WDT_TIMER2_TIMEOUT_STS::SET);
                return;
            }

            // Raise an NMI. NMIs don't fire immediately; a couple instructions is a fairly typicaly delay on VeeR.
            const NMI_DELAY: u64 = 2;

            // From RISC-V_VeeR_EL2_PRM.pdf
            const NMI_CAUSE_WDT_TIMEOUT: u32 = 0x0000_0000; // [TODO] Need correct mcause value.

            self.timer.schedule_action_in(
                NMI_DELAY,
                TimerAction::Nmi {
                    mcause: NMI_CAUSE_WDT_TIMEOUT,
                },
            );
        }
    }

    /// Called by Bus::warm_reset() to indicate a warm reset
    fn bus_warm_reset(&mut self) {
        // Set the reaset reason to 'WARM_RESET'
        self.cptra_reset_reason
            .reg
            .write(ResetReason::WARM_RESET::SET);

        self.fuses_can_be_written = true;
        self.cptra_flow_status
            .reg
            .write(FlowStatus::READY_FOR_FUSES::SET);

        self.reset_common();
    }

    /// Called by Bus::update_reset() to indicate an update reset
    fn bus_update_reset(&mut self) {
        // Upload the update firmware in the mailbox.
        (self.upload_update_fw)(&mut self.mailbox);

        // Set the reaset reason to 'FW_UPD_RESET'
        self.cptra_reset_reason
            .reg
            .write(ResetReason::FW_UPD_RESET::SET);

        self.reset_common();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{root_bus::TbServicesCb, MailboxRam};
    use std::{
        fs::File,
        io::{Read, Write},
        path::{Path, PathBuf},
    };
    use tock_registers::{interfaces::ReadWriteable, registers::InMemoryRegister};

    fn send_data_to_mailbox(mailbox: &mut MailboxInternal, cmd: u32, data: &[u8]) {
        let regs = mailbox.regs();
        while regs.lock().read().lock() {}

        regs.cmd().write(|_| cmd);
        regs.dlen().write(|_| (data.len() as u32));

        let word_size = RvSize::Word as usize;
        let remainder = data.len() % word_size;
        let n = data.len() - remainder;

        for idx in (0..n).step_by(word_size) {
            regs.datain()
                .write(|_| u32::from_le_bytes(data[idx..idx + word_size].try_into().unwrap()));
        }

        // Handle the remainder bytes.
        if remainder > 0 {
            let mut last_word = data[n] as u32;
            for idx in 1..remainder {
                last_word |= (data[n + idx] as u32) << (idx << 3);
            }
            regs.datain().write(|_| last_word);
        }
    }

    fn download_idev_id_csr(
        mailbox: &mut MailboxInternal,
        path: &mut PathBuf,
        soc_reg: &mut SocRegistersInternal,
    ) {
        download_to_file(mailbox, path, "caliptra_idevid_csr.der");

        soc_reg
            .regs
            .borrow_mut()
            .cptra_dbg_manuf_service_reg
            .reg
            .modify(DebugManufService::REQ_IDEVID_CSR::CLEAR)
    }

    fn download_ldev_id_cert(
        mailbox: &mut MailboxInternal,
        path: &mut PathBuf,
        soc_reg: &mut SocRegistersInternal,
    ) {
        download_to_file(mailbox, path, "caliptra_ldevid_cert.der");

        soc_reg
            .regs
            .borrow_mut()
            .cptra_dbg_manuf_service_reg
            .reg
            .modify(DebugManufService::REQ_LDEVID_CERT::CLEAR)
    }

    fn download_to_file(mailbox: &mut MailboxInternal, path: &mut PathBuf, file: &str) {
        path.push(file);
        let mut file = std::fs::File::create(path).unwrap();

        let regs = mailbox.regs();

        let byte_count = regs.dlen().read() as usize;
        let remainder = byte_count % core::mem::size_of::<u32>();
        let n = byte_count - remainder;

        for _ in (0..n).step_by(core::mem::size_of::<u32>()) {
            let buf = regs.dataout().read();
            file.write_all(&buf.to_le_bytes()).unwrap();
        }

        if remainder > 0 {
            let part = regs.dataout().read();
            for idx in 0..remainder {
                let byte = ((part >> (idx << 3)) & 0xFF) as u8;
                file.write_all(&[byte]).unwrap();
            }
        }
        regs.status().write(|w| w.status(|w| w.cmd_complete()));
    }

    #[test]
    fn test_idev_id_csr_download() {
        let data: [u8; 48] = [
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
            0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
            0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        ];
        let pic = Pic::new();
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mut mailbox = MailboxInternal::new(&clock, mailbox_ram);
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        let args = CaliptraRootBusArgs::default();
        let args = CaliptraRootBusArgs { log_dir, ..args };
        let mut soc_reg: SocRegistersInternal =
            SocRegistersInternal::new(&clock, mailbox.clone(), Iccm::new(&clock), &pic, args);

        soc_reg
            .write(RvSize::Word, CPTRA_DBG_MANUF_SERVICE_REG_START, 1)
            .unwrap();

        //
        // [Sender Side]
        //

        // Add csr data to the mailbox.
        send_data_to_mailbox(&mut mailbox, 0xDEADBEEF, &data);
        mailbox
            .regs()
            .status()
            .write(|w| w.status(|w| w.data_ready()));
        mailbox.regs().execute().write(|w| w.execute(true));

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

        // Download the IDEVID CSR.
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        download_idev_id_csr(&mut mailbox, &mut log_dir, &mut soc_reg);

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
        let pic = Pic::new();
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mut mailbox = MailboxInternal::new(&clock, mailbox_ram);
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        let args = CaliptraRootBusArgs::default();
        let args = CaliptraRootBusArgs { log_dir, ..args };
        let mut soc_reg: SocRegistersInternal =
            SocRegistersInternal::new(&clock, mailbox.clone(), Iccm::new(&clock), &pic, args);
        soc_reg
            .write(RvSize::Word, CPTRA_DBG_MANUF_SERVICE_REG_START, 2)
            .unwrap();

        //
        // [Sender Side]
        //

        // Add cert data to the mailbox.
        send_data_to_mailbox(&mut mailbox, 0xDEADBEEF, &data);
        mailbox
            .regs()
            .status()
            .write(|w| w.status(|w| w.data_ready()));
        mailbox.regs().execute().write(|w| w.execute(true));

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

        // Download the LDEVID cert.
        let mut log_dir = PathBuf::new();
        log_dir.push("/tmp");
        download_ldev_id_cert(&mut mailbox, &mut log_dir, &mut soc_reg);

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

        let pic = Pic::new();
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mailbox = MailboxInternal::new(&clock, mailbox_ram);
        let args = CaliptraRootBusArgs {
            tb_services_cb: TbServicesCb::new(move |ch| output2.borrow_mut().push(ch)),
            ..Default::default()
        };
        let mut soc_reg: SocRegistersInternal =
            SocRegistersInternal::new(&clock, mailbox, Iccm::new(&clock), &pic, args);

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, b'h'.into());

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, b'i'.into());

        let _ = soc_reg.write(RvSize::Word, CPTRA_GENERIC_OUTPUT_WIRES_START, 0xff);

        assert_eq!(&*output.borrow(), &vec![b'h', b'i', 0xff]);
    }

    #[test]
    fn test_secrets_when_debug_not_locked() {
        use caliptra_hw_model_types::SecurityState;
        let pic = Pic::new();
        let clock = Clock::new();
        let soc = SocRegistersInternal::new(
            &clock,
            MailboxInternal::new(&clock, MailboxRam::new()),
            Iccm::new(&clock),
            &pic,
            CaliptraRootBusArgs {
                security_state: *SecurityState::default().set_debug_locked(false),
                ..CaliptraRootBusArgs::default()
            },
        );
        soc.external_regs().regs.borrow_mut().fuse_field_entropy = [0x33333333; 8];
        assert_eq!(soc.uds(), [0xff_u8; 48]);
        assert_eq!(soc.field_entropy(), [0xff_u8; 32]);
        assert_eq!(soc.doe_key(), [0xff_u8; 32]);
    }

    #[test]
    fn test_secrets_when_debug_locked() {
        use caliptra_hw_model_types::SecurityState;
        let pic = Pic::new();
        let clock = Clock::new();
        let soc = SocRegistersInternal::new(
            &clock,
            MailboxInternal::new(&clock, MailboxRam::new()),
            Iccm::new(&clock),
            &pic,
            CaliptraRootBusArgs {
                security_state: *SecurityState::default().set_debug_locked(true),
                ..CaliptraRootBusArgs::default()
            },
        );
        soc.external_regs().regs.borrow_mut().fuse_field_entropy = [0x33333333; 8];
        assert_eq!(soc.uds(), SocRegistersImpl::UDS);
        assert_eq!(soc.field_entropy(), [0x33_u8; 32]);
        assert_eq!(soc.doe_key(), crate::root_bus::DEFAULT_DOE_KEY);
    }

    fn next_action(clock: &Clock) -> Option<TimerAction> {
        let mut actions = clock.increment(4);
        match actions.len() {
            0 => None,
            1 => actions.drain().next(),
            _ => panic!("More than one action scheduled; unexpected"),
        }
    }

    #[test]
    fn test_wdt() {
        let pic = Pic::new();
        let clock = Clock::new();
        let mailbox_ram = MailboxRam::new();
        let mailbox = MailboxInternal::new(&clock, mailbox_ram);

        let mut soc_reg: SocRegistersInternal = SocRegistersInternal::new(
            &clock,
            mailbox,
            Iccm::new(&clock),
            &pic,
            CaliptraRootBusArgs::default(),
        );
        soc_reg
            .write(RvSize::Word, CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START, 4)
            .unwrap();
        soc_reg
            .write(RvSize::Word, CPTRA_WDT_TIMER1_TIMEOUT_PERIOD_START + 4, 0)
            .unwrap();
        soc_reg
            .write(RvSize::Word, CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START, 1)
            .unwrap();
        soc_reg
            .write(RvSize::Word, CPTRA_WDT_TIMER2_TIMEOUT_PERIOD_START + 4, 0)
            .unwrap();
        soc_reg
            .write(RvSize::Word, CPTRA_WDT_TIMER1_EN_START, 1)
            .unwrap();

        loop {
            let status = InMemoryRegister::<u32, WdtStatus::Register>::new(
                soc_reg.read(RvSize::Word, CPTRA_WDT_STATUS_START).unwrap(),
            );
            if status.is_set(WdtStatus::T2_TIMEOUT) {
                break;
            }

            clock.increment_and_process_timer_actions(1, &mut soc_reg);
        }

        assert_eq!(
            next_action(&clock),
            Some(TimerAction::Nmi {
                mcause: 0x0000_0000,
            })
        );
    }
}
