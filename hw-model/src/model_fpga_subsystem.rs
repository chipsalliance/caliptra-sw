// Licensed under the Apache-2.0 license

#![allow(clippy::mut_from_ref)]
#![allow(dead_code)]

use crate::api_types::{DeviceLifecycle, Fuses};
use crate::bmc::Bmc;
use crate::fpga_regs::{Control, FifoData, FifoRegs, FifoStatus, ItrngFifoStatus, WrapperRegs};
use crate::keys::{DEFAULT_LIFECYCLE_RAW_TOKENS, DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN};
use crate::mcu_boot_status::McuBootMilestones;
use crate::openocd::openocd_jtag_tap::{JtagParams, JtagTap, OpenOcdJtagTap};
use crate::otp_provision::{
    lc_generate_memory, otp_generate_lifecycle_tokens_mem,
    otp_generate_manuf_debug_unlock_token_mem, otp_generate_sw_manuf_partition_mem,
    LifecycleControllerState, OtpSwManufPartition,
};
use crate::xi3c::XI3cError;
use crate::{
    xi3c, BootParams, Error, HwModel, InitParams, ModelCallback, ModelError, Output, TrngMode,
};
use crate::{OcpLockState, SecurityState};
use anyhow::Result;
use caliptra_api::SocManager;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Device, Event, EventData, RecoveryCommandCode};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::HexSlice;
use caliptra_image_types::FwVerificationPqcKeyType;
use sensitive_mmio::{SensitiveMmio, SensitiveMmioArgs};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uio::{UioDevice, UioError};
use zerocopy::{FromBytes, IntoBytes};

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: (usize, usize) = (0, 0);
const CALIPTRA_MAPPING: (usize, usize) = (0, 1);
const CALIPTRA_ROM_MAPPING: (usize, usize) = (0, 2);
const I3C_CONTROLLER_MAPPING: (usize, usize) = (0, 3);
const OTP_RAM_MAPPING: (usize, usize) = (0, 4);
const LC_MAPPING: (usize, usize) = (1, 0);
const MCU_ROM_MAPPING: (usize, usize) = (1, 1);
const I3C_TARGET_MAPPING: (usize, usize) = (1, 2);
const MCI_MAPPING: (usize, usize) = (1, 3);
const OTP_MAPPING: (usize, usize) = (1, 4);

// TODO(timothytrippel): autogenerate these from the OTP memory map definition
// Offsets in the OTP for all partitions.
// SW_TEST_UNLOCK_PARTITION
const OTP_SW_TEST_UNLOCK_PARTITION_OFFSET: usize = 0x0;
// SW_MANUF_PARTITION
const OTP_SW_MANUF_PARTITION_OFFSET: usize = 0x0F8;
// SECRET_LC_TRANSITION_PARTITION
const OTP_SECRET_LC_TRANSITION_PARTITION_OFFSET: usize = 0x300;
// SVN_PARTITION
const OTP_SVN_PARTITION_OFFSET: usize = 0x3B8;
const OTP_SVN_PARTITION_FMC_SVN_FIELD_OFFSET: usize = OTP_SVN_PARTITION_OFFSET + 0; // 4 bytes
const OTP_SVN_PARTITION_RUNTIME_SVN_FIELD_OFFSET: usize = OTP_SVN_PARTITION_OFFSET + 4; // 16 bytes
const OTP_SVN_PARTITION_SOC_MANIFEST_SVN_FIELD_OFFSET: usize = OTP_SVN_PARTITION_OFFSET + 20; // 16 bytes
const OTP_SVN_PARTITION_SOC_MAX_SVN_FIELD_OFFSET: usize = OTP_SVN_PARTITION_OFFSET + 36; // 1 byte used
                                                                                         // VENDOR_HASHES_MANUF_PARTITION
const OTP_VENDOR_HASHES_MANUF_PARTITION_OFFSET: usize = 0x420;
const FUSE_VENDOR_PKHASH_OFFSET: usize = OTP_VENDOR_HASHES_MANUF_PARTITION_OFFSET;
const FUSE_PQC_OFFSET: usize = OTP_VENDOR_HASHES_MANUF_PARTITION_OFFSET + 48;
// VENDOR_HASHES_PROD_PARTITION
const OTP_VENDOR_HASHES_PROD_PARTITION_OFFSET: usize = 0x460;
const FUSE_OWNER_PKHASH_OFFSET: usize = OTP_VENDOR_HASHES_PROD_PARTITION_OFFSET; // 48 bytes
                                                                                 // VENDOR_REVOCATIONS_PROD_PARTITION
const OTP_VENDOR_REVOCATIONS_PROD_PARTITION_OFFSET: usize = 0x7C0;
const FUSE_VENDOR_ECC_REVOCATION_OFFSET: usize = OTP_VENDOR_REVOCATIONS_PROD_PARTITION_OFFSET + 12; // 4 bytes
const FUSE_VENDOR_LMS_REVOCATION_OFFSET: usize = OTP_VENDOR_REVOCATIONS_PROD_PARTITION_OFFSET + 16; // 4 bytes
const FUSE_VENDOR_REVOCATION_OFFSET: usize = OTP_VENDOR_REVOCATIONS_PROD_PARTITION_OFFSET + 20; // 4 bytes
                                                                                                // LIFECYCLE_PARTITION
                                                                                                // VENDOR_NON_SECRET_PROD_PARTITION
pub const VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET: usize = 0xaa8;
const UDS_SEED_OFFSET: usize = VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET; // 64 bytes
const FIELD_ENTROPY_OFFSET: usize = VENDOR_NON_SECRET_PROD_PARTITION_BYTE_OFFSET + 64; // 32 bytes
                                                                                       // CPTRA_SS_LOCK_HEK_PROD partitions
const OTP_CPTRA_SS_LOCK_HEK_PROD_0_OFFSET: usize = 0xCB0;
const OTP_CPTRA_SS_LOCK_HEK_PROD_1_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_0_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_2_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_1_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_3_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_2_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_4_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_3_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_5_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_4_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_6_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_5_OFFSET + 48;
const OTP_CPTRA_SS_LOCK_HEK_PROD_7_OFFSET: usize = OTP_CPTRA_SS_LOCK_HEK_PROD_6_OFFSET + 48;
// LIFECYCLE_PARTITION
const OTP_LIFECYCLE_PARTITION_OFFSET: usize = 0xE30;

// These are the default physical addresses for the peripherals. The addresses listed in
// FPGA_MEMORY_MAP are physical addresses specific to the FPGA. These addresses are used over the
// FPGA addresses so similar code can be used between the emulator and the FPGA hardware models.
// These are only used for calculating offsets from the virtual addresses retrieved from UIO.
const EMULATOR_I3C_ADDR: usize = 0x2000_4000;
const EMULATOR_I3C_ADDR_RANGE_SIZE: usize = 0x1000;
const EMULATOR_I3C_END_ADDR: usize = EMULATOR_I3C_ADDR + EMULATOR_I3C_ADDR_RANGE_SIZE - 1;
const EMULATOR_MCI_ADDR: usize = 0x2100_0000;
const EMULATOR_MCI_ADDR_RANGE_SIZE: usize = 0xe0_0000;
const EMULATOR_MCI_END_ADDR: usize = EMULATOR_MCI_ADDR + EMULATOR_MCI_ADDR_RANGE_SIZE - 1;

pub(crate) fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

/// Configures the memory map for the MCU.
/// These are the defaults that can be overridden and provided to the ROM and runtime builds.
#[repr(C)]
pub struct McuMemoryMap {
    pub rom_offset: u32,
    pub rom_size: u32,
    pub rom_stack_size: u32,

    pub sram_offset: u32,
    pub sram_size: u32,

    pub pic_offset: u32,

    pub dccm_offset: u32,
    pub dccm_size: u32,

    pub i3c_offset: u32,
    pub i3c_size: u32,

    pub mci_offset: u32,
    pub mci_size: u32,

    pub mbox_offset: u32,
    pub mbox_size: u32,

    pub soc_offset: u32,
    pub soc_size: u32,

    pub otp_offset: u32,
    pub otp_size: u32,

    pub lc_offset: u32,
    pub lc_size: u32,
}

const FPGA_MEMORY_MAP: McuMemoryMap = McuMemoryMap {
    rom_offset: 0xb004_0000,
    rom_size: 128 * 1024,
    rom_stack_size: 0x3000,

    dccm_offset: 0x5000_0000,
    dccm_size: 16 * 1024,

    sram_offset: 0xa8c0_0000,
    sram_size: 384 * 1024,

    pic_offset: 0x6000_0000,

    i3c_offset: 0xa403_0000,
    i3c_size: 0x1000,

    mci_offset: 0xa800_0000,
    mci_size: 0xa0_0028,

    mbox_offset: 0xa412_0000,
    mbox_size: 0x28,

    soc_offset: 0xa413_0000,
    soc_size: 0x5e0,

    otp_offset: 0xa406_0000,
    otp_size: OTP_FULL_SIZE as u32,

    lc_offset: 0xa404_0000,
    lc_size: 0x8c,
};

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0x1;
// we split the OTP memory into two parts: the OTP half and a simulated flash half.
const OTP_FULL_SIZE: usize = 16384;
const FLASH_SIZE: usize = 8192;
const OTP_SIZE: usize = 8192;
const _: () = assert!(OTP_SIZE + FLASH_SIZE == OTP_FULL_SIZE);
const _: () = assert!(OTP_LIFECYCLE_PARTITION_OFFSET + 88 + 8 <= OTP_SIZE);
const AXI_CLK_HZ: u32 = 199_999_000;
const I3C_CLK_HZ: u32 = 12_500_000;

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;
const I3C_WRITE_FIFO_SIZE: u16 = 128;

pub struct Wrapper {
    pub ptr: *mut u32,
}

impl Wrapper {
    pub fn regs(&self) -> &mut WrapperRegs {
        unsafe { &mut *(self.ptr as *mut WrapperRegs) }
    }
    pub fn fifo_regs(&self) -> &mut FifoRegs {
        unsafe { &mut *(self.ptr.offset(0x1000 / 4) as *mut FifoRegs) }
    }
}
unsafe impl Send for Wrapper {}
unsafe impl Sync for Wrapper {}

#[derive(Clone)]
pub struct Mci {
    pub ptr: *mut u32,
}

impl Mci {
    pub fn regs(&self) -> caliptra_registers::mci::RegisterBlock<BusMmio<FpgaRealtimeBus<'_>>> {
        unsafe {
            caliptra_registers::mci::RegisterBlock::new_with_mmio(
                EMULATOR_MCI_ADDR as *mut u32,
                BusMmio::new(FpgaRealtimeBus {
                    mmio: self.ptr,
                    phantom: Default::default(),
                }),
            )
        }
    }
}

#[derive(Clone)]
pub struct XI3CWrapper {
    pub controller: Arc<Mutex<xi3c::Controller>>,
    // TODO: remove pub from these once we know all the ways we need to use them.
    // TODO: Possibly use Mutex to protect access as well.
    pub i3c_mmio: *mut u32,
    pub i3c_controller_mmio: *mut u32,
}

// needed to copy pointers
// Safety: the pointers are themselves perfectly thread-safe since they are static, but
// the underlying hardware behavior may not be guaranteed if they are used by multiple threads.
unsafe impl Send for XI3CWrapper {}
unsafe impl Sync for XI3CWrapper {}

impl XI3CWrapper {
    pub unsafe fn i3c_core(
        &self,
    ) -> caliptra_registers::i3ccsr::RegisterBlock<BusMmio<FpgaRealtimeBus<'_>>> {
        caliptra_registers::i3ccsr::RegisterBlock::new_with_mmio(
            EMULATOR_I3C_ADDR as *mut u32,
            BusMmio::new(FpgaRealtimeBus {
                mmio: self.i3c_mmio,
                phantom: Default::default(),
            }),
        )
    }

    pub const unsafe fn regs(&self) -> &xi3c::XI3c {
        &*(self.i3c_controller_mmio as *const xi3c::XI3c)
    }

    pub fn configure(&self) {
        println!("I3C controller initializing");
        // Safety: we are only reading the register
        println!("XI3C HW version = {:x}", unsafe {
            self.regs().version.get()
        });
        const I3C_MODE: u8 = 1;
        self.controller
            .lock()
            .unwrap()
            .set_s_clk(AXI_CLK_HZ, I3C_CLK_HZ, I3C_MODE);
        self.controller.lock().unwrap().cfg_initialize().unwrap();
        println!("I3C controller finished initializing");
    }

    /// Start receiving data (non-blocking).
    pub fn read_start(&self, len: u16) -> Result<(), XI3cError> {
        let target_addr = self.get_primary_addr();
        let cmd = xi3c::Command {
            no_repeated_start: 1,
            pec: 0,
            target_addr,
            ..Default::default()
        };
        self.controller.lock().unwrap().master_recv(&cmd, len)
    }

    /// Finish receiving data (blocking).
    pub fn read_finish(&self, len: u16) -> Result<Vec<u8>, XI3cError> {
        let target_addr = self.get_primary_addr();
        let cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            pec: 0,
            target_addr,
            ..Default::default()
        };
        self.controller
            .lock()
            .unwrap()
            .master_recv_finish(None, &cmd, len)
    }

    /// Receive data (blocking).
    pub fn read(&self, len: u16) -> Result<Vec<u8>, XI3cError> {
        let target_addr = self.get_primary_addr();
        let cmd = xi3c::Command {
            no_repeated_start: 1,
            target_addr,
            ..Default::default()
        };
        self.controller
            .lock()
            .unwrap()
            .master_recv_polled(None, &cmd, len)
    }

    pub fn get_primary_addr(&self) -> u8 {
        // Safety: we are only reading the register
        let reg = unsafe {
            self.i3c_core()
                .stdby_ctrl_mode()
                .stby_cr_device_addr()
                .read()
        };
        if reg.dynamic_addr_valid() {
            reg.dynamic_addr() as u8
        } else if reg.static_addr_valid() {
            reg.static_addr() as u8
        } else {
            panic!("I3C target does not have a valid address set");
        }
    }

    fn get_recovery_addr(&self) -> u8 {
        // Safety: we are only reading the register
        let reg = unsafe {
            self.i3c_core()
                .stdby_ctrl_mode()
                .stby_cr_virt_device_addr()
                .read()
        };
        if reg.virt_dynamic_addr_valid() {
            reg.virt_dynamic_addr() as u8
        } else if reg.virt_static_addr_valid() {
            reg.virt_static_addr() as u8
        } else {
            panic!("I3C virtual target does not have a valid address set");
        }
    }

    /// Write data and wait for ACK (blocking).
    pub fn write(&self, payload: &[u8]) -> Result<(), XI3cError> {
        let target_addr = self.get_primary_addr();
        let cmd = xi3c::Command {
            no_repeated_start: 1,
            target_addr,
            ..Default::default()
        };
        self.controller
            .lock()
            .unwrap()
            .master_send_polled(&cmd, payload, payload.len() as u16)
    }

    /// Send data but don't wait for ACK (non-blocking).
    pub fn write_nowait(&self, payload: &[u8]) -> Result<(), XI3cError> {
        let target_addr = self.get_primary_addr();
        let cmd = xi3c::Command {
            no_repeated_start: 1,
            target_addr,
            ..Default::default()
        };
        self.controller
            .lock()
            .unwrap()
            .master_send(&cmd, payload, payload.len() as u16)
    }

    pub fn ibi_ready(&self) -> bool {
        self.controller.lock().unwrap().ibi_ready()
    }

    pub fn ibi_recv(&self, timeout: Option<Duration>) -> Result<Vec<u8>, XI3cError> {
        self.controller
            .lock()
            .unwrap()
            .ibi_recv_polled(timeout.unwrap_or(Duration::from_millis(1))) // 256 bytes only takes ~0.2ms to transmit, so this gives us plenty of time
    }

    /// Available space in CMD_FIFO to write
    pub fn cmd_fifo_level(&self) -> u16 {
        self.controller.lock().unwrap().cmd_fifo_level()
    }

    /// Available space in WR_FIFO to write
    pub fn write_fifo_level(&self) -> u16 {
        self.controller.lock().unwrap().write_fifo_level()
    }

    /// Number of RESP status details are available in RESP_FIFO to read
    pub fn resp_fifo_level(&self) -> u16 {
        self.controller.lock().unwrap().resp_fifo_level()
    }

    /// Number of read data words are available in RD_FIFO to read
    pub fn read_fifo_level(&self) -> u16 {
        self.controller.lock().unwrap().read_fifo_level()
    }

    pub fn write_fifo_empty(&self) -> bool {
        self.write_fifo_level() == I3C_WRITE_FIFO_SIZE
    }
}

pub struct ModelFpgaSubsystem {
    pub devs: [UioDevice; 2],
    pub wrapper: Arc<Wrapper>,
    pub caliptra_rom_backdoor: *mut u8,
    pub mcu_rom_backdoor: *mut u8,
    pub otp_mem_backdoor: *mut u8,
    // Reset sensitive MMIO UIO pointers. Accessing these while subsystem is in reset will trigger
    // a kernel panic.
    pub mmio: SensitiveMmio,

    pub realtime_thread: Option<thread::JoinHandle<()>>,
    pub realtime_thread_exit_flag: Arc<AtomicBool>,

    pub fuses: Fuses,
    pub otp_init: Vec<u8>,
    pub output: Output,
    pub recovery_started: bool,
    pub bmc: Bmc,
    pub from_bmc: mpsc::Receiver<Event>,
    pub to_bmc: mpsc::Sender<Event>,
    pub recovery_fifo_blocks: Vec<Vec<u8>>,
    pub recovery_ctrl_len: usize,
    pub recovery_ctrl_written: bool,
    pub bmc_step_counter: usize,
    pub blocks_sent: usize,
    pub enable_mcu_uart_log: bool,
    pub bootfsm_break: bool,
    pub rom_callback: Option<ModelCallback>,
}

impl ModelFpgaSubsystem {
    fn set_bootfsm_break(&mut self, val: bool) {
        if val {
            self.wrapper
                .regs()
                .control
                .modify(Control::BootfsmBrkpoint::SET);
        } else {
            self.wrapper
                .regs()
                .control
                .modify(Control::BootfsmBrkpoint::CLEAR);
        }
    }

    fn set_ss_ocp_lock(&mut self, val: bool) {
        if val {
            self.wrapper.regs().control.modify(Control::OcpLockEn::SET);
        } else {
            self.wrapper
                .regs()
                .control
                .modify(Control::OcpLockEn::CLEAR);
        }
    }

    fn set_ss_debug_intent(&mut self, val: bool) {
        if val {
            self.wrapper
                .regs()
                .control
                .modify(Control::SsDebugIntent::SET);
        } else {
            self.wrapper
                .regs()
                .control
                .modify(Control::SsDebugIntent::CLEAR);
        }
    }

    fn set_ss_rma_or_scrap_ppd(&mut self, val: bool) {
        if val {
            self.wrapper
                .regs()
                .control
                .modify(Control::LcAllowRmaOrScrapOnPpd::SET);
        } else {
            self.wrapper
                .regs()
                .control
                .modify(Control::LcAllowRmaOrScrapOnPpd::CLEAR);
        }
    }

    fn set_raw_unlock_token_hash(&mut self, token_hash: &[u32; 4]) {
        for i in 0..token_hash.len() {
            self.wrapper.regs().cptr_ss_raw_unlock_token_hash[i].set(token_hash[i]);
        }
    }

    fn axi_reset(&mut self) {
        self.wrapper.regs().control.modify(Control::AxiReset.val(1));
        // wait a few clock cycles or we can crash the FPGA
        std::thread::sleep(std::time::Duration::from_micros(1));
    }

    pub fn set_subsystem_reset(&mut self, reset: bool) {
        if reset {
            self.mmio.disable();
        }
        self.wrapper.regs().control.modify(
            Control::CptraSsRstB.val((!reset) as u32) + Control::CptraPwrgood.val((!reset) as u32),
        );
        if !reset {
            self.mmio.enable();
        }
    }

    pub fn set_cptra_ss_rst_b(&mut self, value: bool) {
        self.wrapper
            .regs()
            .control
            .modify(Control::CptraSsRstB.val(value as u32));
    }

    fn set_secrets_valid(&mut self, value: bool) {
        self.wrapper.regs().control.modify(
            Control::CptraObfUdsSeedVld.val(value as u32)
                + Control::CptraObfFieldEntropyVld.val(value as u32),
        )
    }

    fn clear_logs(&mut self) {
        println!("Clearing Caliptra logs");
        loop {
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            if !self
                .wrapper
                .fifo_regs()
                .log_fifo_data
                .is_set(FifoData::CharValid)
            {
                break;
            }
        }

        println!("Clearing MCU logs");
        loop {
            if self
                .wrapper
                .fifo_regs()
                .dbg_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            if !self
                .wrapper
                .fifo_regs()
                .dbg_fifo_data_pop
                .is_set(FifoData::CharValid)
            {
                break;
            }
        }
    }

    fn handle_log(&mut self) {
        loop {
            // Check if the FIFO is full (which probably means there was an overrun)
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Full)
            {
                panic!("FPGA log FIFO overran");
            }
            if self
                .wrapper
                .fifo_regs()
                .log_fifo_status
                .is_set(FifoStatus::Empty)
            {
                break;
            }
            let data = self.wrapper.fifo_regs().log_fifo_data.extract();
            // Add byte to log if it is valid
            if data.is_set(FifoData::CharValid) {
                self.output()
                    .sink()
                    .push_uart_char(data.read(FifoData::NextChar) as u8);
            }
        }

        if self.enable_mcu_uart_log {
            loop {
                // Check if the FIFO is full (which probably means there was an overrun)
                if self
                    .wrapper
                    .fifo_regs()
                    .dbg_fifo_status
                    .is_set(FifoStatus::Full)
                {
                    panic!("FPGA log FIFO overran");
                }
                if self
                    .wrapper
                    .fifo_regs()
                    .dbg_fifo_status
                    .is_set(FifoStatus::Empty)
                {
                    break;
                }
                let data = self.wrapper.fifo_regs().dbg_fifo_data_pop.extract();
                // Add byte to log if it is valid
                if data.is_set(FifoData::CharValid) {
                    self.output()
                        .sink()
                        .push_uart_char(data.read(FifoData::NextChar) as u8);
                }
            }
        }
    }

    // UIO crate doesn't provide a way to unmap memory.
    pub fn unmap_mapping(&self, addr: *mut u32, mapping: (usize, usize)) {
        let map_size = self.devs[mapping.0].map_size(mapping.1).unwrap();

        unsafe {
            nix::sys::mman::munmap(addr as *mut libc::c_void, map_size).unwrap();
        }
    }

    fn realtime_thread_itrng_fn(
        wrapper: Arc<Wrapper>,
        running: Arc<AtomicBool>,
        mut itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,
    ) {
        // Reset ITRNG FIFO to clear out old data

        wrapper
            .fifo_regs()
            .itrng_fifo_status
            .write(ItrngFifoStatus::Reset::SET);
        wrapper
            .fifo_regs()
            .itrng_fifo_status
            .write(ItrngFifoStatus::Reset::CLEAR);

        // Small delay to allow reset to complete
        thread::sleep(Duration::from_millis(1));

        while running.load(Ordering::Relaxed) {
            // Once TRNG data is requested the FIFO will continously empty. Load at max one FIFO load at a time.
            // FPGA ITRNG FIFO is 1024 DW deep.
            for _ in 0..FPGA_ITRNG_FIFO_SIZE {
                if !wrapper
                    .fifo_regs()
                    .itrng_fifo_status
                    .is_set(ItrngFifoStatus::Full)
                {
                    let mut itrng_dw = 0;
                    for i in 0..8 {
                        match itrng_nibbles.next() {
                            Some(nibble) => itrng_dw += u32::from(nibble) << (4 * i),
                            None => return,
                        }
                    }
                    wrapper.fifo_regs().itrng_fifo_data.set(itrng_dw);
                } else {
                    break;
                }
            }
            // 1 second * (20 MHz / (2^13 throttling counter)) / 8 nibbles per DW: 305 DW of data consumed in 1 second.
            let end_time = Instant::now() + Duration::from_millis(1000);
            while running.load(Ordering::Relaxed) && Instant::now() < end_time {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    pub fn i3c_core(
        &mut self,
    ) -> Option<caliptra_registers::i3ccsr::RegisterBlock<BusMmio<FpgaRealtimeBus<'_>>>> {
        self.mmio.i3c_core()
    }

    pub fn i3c_controller(&self) -> Option<XI3CWrapper> {
        self.mmio.i3c_controller().clone()
    }

    pub fn i3c_target_configured(&mut self) -> bool {
        u32::from(
            self.i3c_core()
                .unwrap()
                .stdby_ctrl_mode()
                .stby_cr_device_addr()
                .read(),
        ) != 0
    }

    pub fn start_recovery_bmc(&mut self) {
        self.recovery_started = true;
    }

    fn bmc_step(&mut self) {
        if !self.recovery_started {
            return;
        }

        self.bmc_step_counter += 1;

        // check if we need to fill the recovey FIFO
        if !self.recovery_fifo_blocks.is_empty() {
            if !self.recovery_ctrl_written {
                let status = self
                    .i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .device_status_0()
                    .read()
                    .dev_status();

                if status != 3 && self.bmc_step_counter % 65536 == 0 {
                    println!("Waiting for device status to be 3, currently: {}", status);
                    return;
                }

                // wait for any other packets to be sent
                if !self.i3c_controller().unwrap().write_fifo_empty() {
                    return;
                }

                let len = ((self.recovery_ctrl_len / 4) as u32).to_le_bytes();
                let mut ctrl = vec![0, 1]; // CMS = 0, reset FIFO
                ctrl.extend_from_slice(&len);

                println!("Writing Indirect fifo ctrl: {:x?}", ctrl);
                self.recovery_block_write_request(RecoveryCommandCode::IndirectFifoCtrl, &ctrl);

                let reported_len = self
                    .i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .indirect_fifo_ctrl_1()
                    .read();

                println!("I3C core reported length: {}", reported_len);
                if reported_len as usize != self.recovery_ctrl_len / 4 {
                    println!(
                        "I3C core reported length should have been {}",
                        self.recovery_ctrl_len / 4
                    );

                    self.print_i3c_registers();

                    panic!(
                        "I3C core reported length should have been {}",
                        self.recovery_ctrl_len / 4
                    );
                }
                self.recovery_ctrl_written = true;
            }
            let fifo_status = self
                .i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_status_0()
                .read();

            // fifo is empty, send a block
            if fifo_status.empty() {
                let chunk = self.recovery_fifo_blocks.pop().unwrap();
                self.blocks_sent += 1;
                self.recovery_block_write_request(RecoveryCommandCode::IndirectFifoData, &chunk);
                return;
            }
        }

        let status = self
            .i3c_core()
            .unwrap()
            .sec_fw_recovery_if()
            .recovery_status()
            .read()
            .dev_rec_status();
        const DEVICE_RECOVERY_STATUS_COMPLETE: u32 = 3;
        if status == DEVICE_RECOVERY_STATUS_COMPLETE {
            println!("Recovery complete; device recovery status: 0x{:x}", status);
            self.recovery_started = false;
            return;
        }

        // don't run the BMC every time as it can spam requests
        if self.bmc_step_counter < 100_000 || self.bmc_step_counter % 10_000 != 0 {
            return;
        }
        self.bmc.step();

        // we need to translate from the BMC events to the I3C controller block reads and writes
        let Ok(event) = self.from_bmc.try_recv() else {
            return;
        };
        // ignore messages that aren't meant for Caliptra core.
        if !matches!(event.dest, Device::CaliptraCore) {
            return;
        }
        match event.event {
            EventData::RecoveryBlockReadRequest {
                source_addr,
                target_addr,
                command_code,
            } => {
                // println!("From BMC: Recovery block read request {:?}", command_code);

                if let Some(payload) = self.recovery_block_read_request(command_code) {
                    self.to_bmc
                        .send(Event {
                            src: Device::CaliptraCore,
                            dest: Device::BMC,
                            event: EventData::RecoveryBlockReadResponse {
                                source_addr: target_addr,
                                target_addr: source_addr,
                                command_code,
                                payload,
                            },
                        })
                        .unwrap();
                }
            }
            EventData::RecoveryBlockReadResponse {
                source_addr: _,
                target_addr: _,
                command_code: _,
                payload: _,
            } => todo!(),
            EventData::RecoveryBlockWrite {
                source_addr: _,
                target_addr: _,
                command_code,
                payload,
            } => {
                //println!("Recovery block write request: {:?}", command_code);

                self.recovery_block_write_request(command_code, &payload);
            }
            EventData::RecoveryImageAvailable { image_id: _, image } => {
                // do the indirect fifo thing
                println!("Recovery image available; writing blocks");

                self.recovery_ctrl_len = image.len();
                self.recovery_ctrl_written = false;

                self.recovery_fifo_blocks = image.chunks(256).map(|chunk| chunk.to_vec()).collect();
                self.recovery_fifo_blocks.reverse(); // reverse so we can pop from the end
            }
            _ => todo!(),
        }
    }

    fn command_code_to_u8(command: RecoveryCommandCode) -> u8 {
        match command {
            RecoveryCommandCode::ProtCap => 34,
            RecoveryCommandCode::DeviceId => 35,
            RecoveryCommandCode::DeviceStatus => 36,
            RecoveryCommandCode::DeviceReset => 37,
            RecoveryCommandCode::RecoveryCtrl => 38,
            RecoveryCommandCode::RecoveryStatus => 39,
            RecoveryCommandCode::HwStatus => 40,
            RecoveryCommandCode::IndirectCtrl => 41,
            RecoveryCommandCode::IndirectStatus => 42,
            RecoveryCommandCode::IndirectData => 43,
            RecoveryCommandCode::Vendor => 44,
            RecoveryCommandCode::IndirectFifoCtrl => 45,
            RecoveryCommandCode::IndirectFifoStatus => 46,
            RecoveryCommandCode::IndirectFifoData => 47,
        }
    }

    fn command_code_to_len(command: RecoveryCommandCode) -> (u16, u16) {
        match command {
            RecoveryCommandCode::ProtCap => (15, 15),
            RecoveryCommandCode::DeviceId => (24, 255),
            RecoveryCommandCode::DeviceStatus => (7, 255),
            RecoveryCommandCode::DeviceReset => (3, 3),
            RecoveryCommandCode::RecoveryCtrl => (3, 3),
            RecoveryCommandCode::RecoveryStatus => (2, 2),
            RecoveryCommandCode::HwStatus => (4, 255),
            RecoveryCommandCode::IndirectCtrl => (6, 6),
            RecoveryCommandCode::IndirectStatus => (6, 6),
            RecoveryCommandCode::IndirectData => (1, 252),
            RecoveryCommandCode::Vendor => (1, 255),
            RecoveryCommandCode::IndirectFifoCtrl => (6, 6),
            RecoveryCommandCode::IndirectFifoStatus => (20, 20),
            RecoveryCommandCode::IndirectFifoData => (1, 4095),
        }
    }

    fn print_i3c_registers(&mut self) {
        println!("Dumping registers");
        println!(
            "sec_fw_recovery_if_prot_cap_0: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .prot_cap_0()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_1: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .prot_cap_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_2: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .prot_cap_2()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_3: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .prot_cap_3()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .device_id_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_1: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_2: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_3: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_4: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_5: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_5()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_reserved: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .device_id_reserved()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .device_status_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_1: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .device_status_1()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_reset: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .device_reset()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_ctrl: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .recovery_ctrl()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_status: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .recovery_status()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_hw_status: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .hw_status()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .indirect_fifo_ctrl_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_1: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_ctrl_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .unwrap()
                    .sec_fw_recovery_if()
                    .indirect_fifo_status_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_1: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_status_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_2: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_status_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_3: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_status_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_4: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_status_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_reserved: {:08x}",
            self.i3c_core()
                .unwrap()
                .sec_fw_recovery_if()
                .indirect_fifo_reserved()
                .read()
                .swap_bytes()
        );
    }

    // send a recovery block read request to the I3C target
    fn recovery_block_read_request(&mut self, command: RecoveryCommandCode) -> Option<Vec<u8>> {
        // per the recovery spec, this maps to a private write and private read

        let target_addr = self.i3c_controller().unwrap().get_recovery_addr();

        // First we write the recovery command code for the block we want
        let mut cmd = xi3c::Command {
            no_repeated_start: 0, // we want the next command (read) to be Sr
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = Self::command_code_to_u8(command);

        let start = self.cycle_count();
        while !self.i3c_controller().unwrap().write_fifo_empty() {
            if self.cycle_count() - start > 1_000_000 {
                //                panic!("Timeout waiting for I3C write FIFO to be empty");
            }
        }

        if self
            .i3c_controller()
            .unwrap()
            .controller
            .lock()
            .unwrap()
            .master_send_polled(&cmd, &[recovery_command_code], 1)
            .is_err()
        {
            return None;
        }

        // then we send a private read for the minimum length
        let len_range = Self::command_code_to_len(command);
        cmd.pec = 0;

        self.i3c_controller()
            .unwrap()
            .controller
            .lock()
            .unwrap()
            .master_recv(&cmd, len_range.0 + 2)
            .expect("Failed to receive ack from target");

        // read in the length, lsb then msb
        let resp = self
            .i3c_controller()
            .unwrap()
            .controller
            .lock()
            .unwrap()
            .master_recv_finish(
                Some(self.realtime_thread_exit_flag.clone()),
                &cmd,
                len_range.0 + 2,
            )
            .unwrap_or_else(|_| panic!("Expected to read {}+ bytes", len_range.0 + 2));

        if resp.len() < 2 {
            panic!("Expected to read at least 2 bytes from target for recovery block length");
        }
        let len = u16::from_le_bytes([resp[0], resp[1]]);
        if len < len_range.0 || len > len_range.1 {
            self.print_i3c_registers();
            panic!(
                "Reading block {:?} expected to read between {} and {} bytes from target, got {}",
                command, len_range.0, len_range.1, len
            );
        }
        let len = len as usize;
        let left = len - (resp.len() - 2);
        // read the rest of the bytes
        if left > 0 {
            // TODO: if the length is more than the minimum we need to abort and restart with the correct value
            // because the xi3c controller does not support variable reads.
            todo!()
        }
        Some(resp[2..].to_vec())
    }

    // send a recovery block write request to the I3C target
    fn recovery_block_write_request(&mut self, command: RecoveryCommandCode, payload: &[u8]) {
        // per the recovery spec, this maps to a private write

        let target_addr = self.i3c_controller().unwrap().get_recovery_addr();
        let cmd = xi3c::Command {
            no_repeated_start: 1,
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = Self::command_code_to_u8(command);

        let mut data = vec![recovery_command_code];
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(payload);

        let start = self.cycle_count();
        while !self.i3c_controller().unwrap().write_fifo_empty() {
            if self.cycle_count() - start > 1_000_000 {
                //                panic!("Timeout waiting for I3C write FIFO to be empty");
            }
        }

        assert!(
            self.i3c_controller()
                .unwrap()
                .controller
                .lock()
                .unwrap()
                .master_send_polled(&cmd, &data, data.len() as u16)
                .is_ok(),
            "Failed to ack write message sent to target"
        );
    }

    pub fn init_otp(&self, security_state: Option<&SecurityState>) -> Result<(), Box<dyn Error>> {
        let mut otp_data = self.otp_slice().to_vec();
        if !self.otp_init.is_empty() {
            // write the initial contents of the OTP memory
            println!("Initializing OTP with initialized data");
            if self.otp_init.len() > otp_data.len() {
                Err(format!(
                    "OTP initialization data is larger than OTP memory {} > {}",
                    self.otp_init.len(),
                    otp_data.len(),
                ))?;
            }
            otp_data[..self.otp_init.len()].copy_from_slice(&self.otp_init);
        }

        if let Some(security_state) = security_state {
            let lc_state = match security_state.device_lifecycle() {
                DeviceLifecycle::Unprovisioned => LifecycleControllerState::TestUnlocked0,
                DeviceLifecycle::Manufacturing => LifecycleControllerState::Dev,
                DeviceLifecycle::Reserved2 => LifecycleControllerState::Raw,
                DeviceLifecycle::Production => LifecycleControllerState::Prod,
            };
            println!("Provisioning lifecycle partition (State: {}).", lc_state);
            let mem = lc_generate_memory(lc_state, 1)?;
            let offset = OTP_LIFECYCLE_PARTITION_OFFSET;
            otp_data[offset..offset + mem.len()].copy_from_slice(&mem);
        }

        // Provision default LC tokens.
        println!("Provisioning SECRET_LC_TRANSITION partition.");
        let tokens = &DEFAULT_LIFECYCLE_RAW_TOKENS;
        let mem = otp_generate_lifecycle_tokens_mem(tokens)?;
        let offset = OTP_SECRET_LC_TRANSITION_PARTITION_OFFSET;
        otp_data[offset..offset + mem.len()].copy_from_slice(&mem);

        // Provision default SW_TEST_UNLOCK partition (manuf debug unlock token).
        println!("Provisioning SW_TEST_UNLOCK partition.");
        let mem = otp_generate_manuf_debug_unlock_token_mem(&DEFAULT_MANUF_DEBUG_UNLOCK_RAW_TOKEN)?;
        let offset = OTP_SW_TEST_UNLOCK_PARTITION_OFFSET;
        otp_data[offset..offset + mem.len()].copy_from_slice(&mem);

        // Provision default SW_MANUF partition.
        // TODO(timothytrippel): enable provisioning prod debug unlock public key hashes for public
        // keys passed in `prod_dbg_unlock_keypairs` field in InitParams.
        println!("Provisioning SW_MANUF partition.");
        let mem =
            otp_generate_sw_manuf_partition_mem(&OtpSwManufPartition {
                anti_rollback_disable: u32::from(self.fuses.anti_rollback_disable),
                idevid_cert_attr: self
                    .fuses
                    .idevid_cert_attr
                    .iter()
                    .fold(vec![], |mut acc, f| {
                        let bytes = f.to_le_bytes();
                        acc.extend_from_slice(&bytes);
                        acc
                    })
                    .try_into()
                    .unwrap(),
                hsm_id: self.fuses.idevid_manuf_hsm_id.iter().enumerate().fold(
                    0,
                    |mut acc, (f, i)| {
                        acc |= (f as u128) << (i * 32);
                        acc
                    },
                ),
                stepping_id: self.fuses.soc_stepping_id as u32,
                ..Default::default()
            })?;
        let offset = OTP_SW_MANUF_PARTITION_OFFSET;
        otp_data[offset..offset + mem.len()].copy_from_slice(&mem);

        // Provision UDS seed in SECRET_MANUF partition
        println!("Provisioning UDS seed in SECRET_MANUF partition.");
        let uds_seed_bytes: Vec<u8> = self
            .fuses
            .uds_seed
            .iter()
            .flat_map(|&word| word.to_le_bytes())
            .collect();
        println!("Setting UDS seed to {:x?}", HexSlice(&uds_seed_bytes));
        otp_data[UDS_SEED_OFFSET..UDS_SEED_OFFSET + uds_seed_bytes.len()]
            .copy_from_slice(&uds_seed_bytes);

        // Provision field entropy in SECRET_MANUF partition
        println!("Provisioning field entropy in SECRET_MANUF partition.");
        let field_entropy_bytes: Vec<u8> = self
            .fuses
            .field_entropy
            .iter()
            .flat_map(|&word| word.to_le_bytes())
            .collect();
        println!(
            "Setting field entropy to {:x?}",
            HexSlice(&field_entropy_bytes)
        );
        otp_data[FIELD_ENTROPY_OFFSET..FIELD_ENTROPY_OFFSET + field_entropy_bytes.len()]
            .copy_from_slice(&field_entropy_bytes);

        let vendor_pk_hash = self.fuses.vendor_pk_hash.as_bytes();
        println!(
            "Setting vendor public key hash to {:x?}",
            HexSlice(vendor_pk_hash)
        );
        otp_data[FUSE_VENDOR_PKHASH_OFFSET..FUSE_VENDOR_PKHASH_OFFSET + vendor_pk_hash.len()]
            .copy_from_slice(vendor_pk_hash);

        let vendor_pqc_type = FwVerificationPqcKeyType::from_u8(self.fuses.fuse_pqc_key_type as u8)
            .unwrap_or(FwVerificationPqcKeyType::LMS);
        println!(
            "Setting vendor public key pqc type to {:x?}",
            vendor_pqc_type
        );
        let val = match vendor_pqc_type {
            FwVerificationPqcKeyType::MLDSA => 0,
            FwVerificationPqcKeyType::LMS => 1,
        };
        otp_data[FUSE_PQC_OFFSET] = val;

        // Owner public key hash (48 bytes) lives in VENDOR_HASHES_PROD partition
        let owner_pk_hash = self.fuses.owner_pk_hash.as_bytes();
        println!(
            "Setting owner public key hash to {:x?}",
            HexSlice(owner_pk_hash)
        );
        otp_data[FUSE_OWNER_PKHASH_OFFSET..FUSE_OWNER_PKHASH_OFFSET + owner_pk_hash.len()]
            .copy_from_slice(owner_pk_hash);

        // Owner revocation fields (ECC, LMS, MLDSA) in VENDOR_REVOCATIONS_PROD partition
        // Note: ECC revocation in API is a 4-bit value; store in low bits of u32 here.
        let vendor_ecc_revocation: u32 = (u32::from(self.fuses.fuse_ecc_revocation)) & 0xF;
        let vendor_lms_revocation: u32 = self.fuses.fuse_lms_revocation;
        let vendor_mldsa_revocation: u32 = self.fuses.fuse_mldsa_revocation;
        println!(
            "Setting owner revocations ecc={:#x} lms={:#x} mldsa={:#x}",
            vendor_ecc_revocation, vendor_lms_revocation, vendor_mldsa_revocation
        );
        otp_data[FUSE_VENDOR_ECC_REVOCATION_OFFSET..FUSE_VENDOR_ECC_REVOCATION_OFFSET + 4]
            .copy_from_slice(&vendor_ecc_revocation.to_le_bytes());
        otp_data[FUSE_VENDOR_LMS_REVOCATION_OFFSET..FUSE_VENDOR_LMS_REVOCATION_OFFSET + 4]
            .copy_from_slice(&vendor_lms_revocation.to_le_bytes());
        otp_data[FUSE_VENDOR_REVOCATION_OFFSET..FUSE_VENDOR_REVOCATION_OFFSET + 4]
            .copy_from_slice(&vendor_mldsa_revocation.to_le_bytes());

        // Firmware/runtime SVN (16 bytes -> 4 words)
        let fw_svn = self.fuses.fw_svn.as_bytes();
        println!("Setting runtime FW SVN to {:x?}", HexSlice(fw_svn));
        otp_data[OTP_SVN_PARTITION_RUNTIME_SVN_FIELD_OFFSET
            ..OTP_SVN_PARTITION_RUNTIME_SVN_FIELD_OFFSET + fw_svn.len()]
            .copy_from_slice(fw_svn);

        // SoC manifest SVN (16 bytes -> 4 words)
        let soc_manifest_svn = self.fuses.soc_manifest_svn.as_bytes();
        println!(
            "Setting SoC manifest SVN to {:x?}",
            HexSlice(soc_manifest_svn)
        );
        otp_data[OTP_SVN_PARTITION_SOC_MANIFEST_SVN_FIELD_OFFSET
            ..OTP_SVN_PARTITION_SOC_MANIFEST_SVN_FIELD_OFFSET + soc_manifest_svn.len()]
            .copy_from_slice(soc_manifest_svn);

        println!("Provisioning CPTRA_SS_LOCK_HEK_PROD_0 partition.");
        let hek_seed_bytes = self.fuses.hek_seed.as_bytes();
        let offset = OTP_CPTRA_SS_LOCK_HEK_PROD_0_OFFSET;
        otp_data[offset..offset + hek_seed_bytes.len()].copy_from_slice(hek_seed_bytes);

        // Max SOC Manifest SVN (1 byte used)
        println!(
            "Burning fuse for SOC MAX SVN {}",
            self.fuses.soc_manifest_max_svn
        );
        otp_data[OTP_SVN_PARTITION_SOC_MAX_SVN_FIELD_OFFSET] = self.fuses.soc_manifest_max_svn;

        self.otp_slice().copy_from_slice(&otp_data);

        Ok(())
    }

    pub fn otp_slice(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.otp_mem_backdoor, OTP_SIZE) }
    }

    pub fn flash_slice(&self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.otp_mem_backdoor.offset(OTP_SIZE as isize),
                FLASH_SIZE,
            )
        }
    }

    pub fn print_otp_memory(&self) {
        let otp = self.otp_slice();
        for (i, oi) in otp.iter().copied().enumerate() {
            if oi != 0 {
                println!("OTP mem: {:03x}: {:02x}", i, oi);
            }
        }
    }

    pub fn mci_flow_status(&mut self) -> u32 {
        self.mmio.mci().unwrap().regs().fw_flow_status().read()
    }

    pub fn mci_boot_checkpoint(&mut self) -> u16 {
        (self.mci_flow_status() & 0x0000_ffff) as u16
    }

    pub fn mci_boot_milestones(&mut self) -> McuBootMilestones {
        McuBootMilestones::from((self.mci_flow_status() >> 16) as u16)
    }

    fn caliptra_axi_bus(&mut self) -> Option<FpgaRealtimeBus<'_>> {
        self.mmio.caliptra_axi_bus()
    }

    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.wrapper.regs().generic_input_wires[i].set(wire);
        }
    }

    fn set_mci_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.wrapper.regs().mci_generic_input_wires[i].set(wire);
        }
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        self.wrapper.regs().itrng_divisor.set(divider - 1);
    }

    fn cycle_count(&mut self) -> u64 {
        self.wrapper.regs().cycle_count.get() as u64
    }

    pub fn jtag_tap_connect(
        &mut self,
        params: &JtagParams,
        tap: JtagTap,
    ) -> Result<Box<OpenOcdJtagTap>> {
        Ok(OpenOcdJtagTap::new(params, tap)?)
    }
}

impl HwModel for ModelFpgaSubsystem {
    type TBus<'a> = FpgaRealtimeBus<'a>;

    fn trng_mode(&self) -> TrngMode {
        TrngMode::Internal
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus {
            mmio: self.mmio.caliptra_mmio().unwrap(),
            phantom: Default::default(),
        }
    }

    fn step(&mut self) {
        self.handle_log();
        self.bmc_step();
    }

    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        if let Some(TrngMode::External) = params.trng_mode {
            return Err("External TRNG mode is not supported in ModelFpgaSubsystem".into());
        }
        let mcu_rom =
            match params.ss_init_params.mcu_rom {
                Some(mcu_rom) => mcu_rom,
                None => &std::fs::read(std::env::var("CPTRA_MCU_ROM").expect(
                    "set the ENV VAR CPTRA_MCU_ROM to the absolute path of caliptra-mcu rom",
                ))
                .expect("couldn't read CPTRA_MCU_ROM"),
            };

        let output = Output::new(params.log_writer);
        let dev0 = UioDevice::blocking_new(0)?;
        let dev1 = UioDevice::blocking_new(1)?;
        let devs = [dev0, dev1];

        let wrapper = Arc::new(Wrapper {
            ptr: devs[FPGA_WRAPPER_MAPPING.0]
                .map_mapping(FPGA_WRAPPER_MAPPING.1)
                .map_err(fmt_uio_error)? as *mut u32,
        });
        let caliptra_rom_backdoor = devs[CALIPTRA_ROM_MAPPING.0]
            .map_mapping(CALIPTRA_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let caliptra_rom_size = devs[CALIPTRA_ROM_MAPPING.0]
            .map_size(CALIPTRA_ROM_MAPPING.1)
            .map_err(fmt_uio_error)?;
        let otp_mem_backdoor = devs[OTP_RAM_MAPPING.0]
            .map_mapping(OTP_RAM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_rom_backdoor = devs[MCU_ROM_MAPPING.0]
            .map_mapping(MCU_ROM_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u8;
        let mcu_rom_size = devs[MCU_ROM_MAPPING.0]
            .map_size(MCU_ROM_MAPPING.1)
            .map_err(fmt_uio_error)?;
        let mci_ptr = devs[MCI_MAPPING.0]
            .map_mapping(MCI_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let caliptra_mmio = devs[CALIPTRA_MAPPING.0]
            .map_mapping(CALIPTRA_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let i3c_mmio = devs[I3C_TARGET_MAPPING.0]
            .map_mapping(I3C_TARGET_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let i3c_controller_mmio = devs[I3C_CONTROLLER_MAPPING.0]
            .map_mapping(I3C_CONTROLLER_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let lc_mmio = devs[LC_MAPPING.0]
            .map_mapping(LC_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let otp_mmio = devs[OTP_MAPPING.0]
            .map_mapping(OTP_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;

        let realtime_thread_exit_flag = Arc::new(AtomicBool::new(true));
        let realtime_thread_exit_flag2 = realtime_thread_exit_flag.clone();
        let realtime_wrapper = wrapper.clone();

        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: i3c_controller_mmio,
            input_clock_hz: AXI_CLK_HZ,
            rw_fifo_depth: 16,
            wr_threshold: 12 * 4, // in bytes
            device_count: 1,
            ibi_capable: true,
            hj_capable: false,
            entdaa_enable: true,
            known_static_addrs: vec![0x3a, 0x3b],
        };
        let i3c_controller = xi3c::Controller::new(xi3c_config);

        let (caliptra_cpu_event_sender, from_bmc) = mpsc::channel();
        let (to_bmc, caliptra_cpu_event_recv) = mpsc::channel();

        // these aren't used
        let (mcu_cpu_event_sender, mcu_cpu_event_recv) = mpsc::channel();

        // This is a fake BMC that runs the recovery flow as a series of events for recovery block reads and writes.
        let bmc = Bmc::new(
            caliptra_cpu_event_sender,
            caliptra_cpu_event_recv,
            mcu_cpu_event_sender,
            mcu_cpu_event_recv,
        );

        let mut m = Self {
            devs,
            wrapper,
            caliptra_rom_backdoor,
            mcu_rom_backdoor,
            otp_mem_backdoor,
            mmio: SensitiveMmio::new(SensitiveMmioArgs {
                caliptra_mmio,
                mci: Mci { ptr: mci_ptr },
                i3c_mmio,
                i3c_controller_mmio,
                i3c_controller: XI3CWrapper {
                    controller: Arc::new(Mutex::new(i3c_controller)),
                    i3c_mmio,
                    i3c_controller_mmio,
                },
                lc_mmio,
                otp_mmio,
            }),

            otp_init: vec![],
            fuses: params.fuses,
            realtime_thread: None,
            realtime_thread_exit_flag,

            output,
            recovery_started: false,
            bmc,
            from_bmc,
            to_bmc,
            recovery_fifo_blocks: vec![],
            bmc_step_counter: 0,
            blocks_sent: 0,
            recovery_ctrl_written: false,
            recovery_ctrl_len: 0,
            enable_mcu_uart_log: params.ss_init_params.enable_mcu_uart_log,
            bootfsm_break: params.bootfsm_break,
            rom_callback: params.rom_callback,
        };

        println!("AXI reset");
        m.axi_reset();

        // Wait until after AXI reset to start the thread so we can guarantee the wrapper is not
        // used while reset is happening. Doing so could cause the AXI bus to hang.
        m.realtime_thread = Some(std::thread::spawn(move || {
            Self::realtime_thread_itrng_fn(
                realtime_wrapper,
                realtime_thread_exit_flag2,
                params.itrng_nibbles,
            )
        }));

        // Set generic input wires.
        let input_wires = [(!params.uds_fuse_row_granularity_64 as u32) << 31, 0];
        m.set_generic_input_wires(&input_wires);

        m.set_mci_generic_input_wires(&[0, 0]);

        println!("Set itrng divider");
        // Set divisor for ITRNG throttling
        m.set_itrng_divider(ITRNG_DIVISOR);

        println!("Set deobf key");
        // Set deobfuscation key
        for i in 0..8 {
            m.wrapper.regs().cptra_obf_key[i].set(params.cptra_obf_key[i]);
        }

        // Set the CSR HMAC key
        for i in 0..16 {
            m.wrapper.regs().cptra_csr_hmac_key[i].set(params.csr_hmac_key[i]);
        }

        // Currently not using strap UDS and FE
        m.set_secrets_valid(false);

        println!("Putting subsystem into reset");
        m.set_subsystem_reset(true);

        m.init_otp(Some(&params.security_state))?;

        println!("Clearing fifo");
        // Sometimes there's garbage in here; clean it out
        m.clear_logs();

        println!("new_unbooted");

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        println!("AXI user written {:x}", DEFAULT_AXI_PAUSER);

        // copy the ROM data
        println!("Writing Caliptra ROM");
        let mut caliptra_rom_data = vec![0; caliptra_rom_size];
        caliptra_rom_data[..params.rom.len()].clone_from_slice(params.rom);

        let caliptra_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.caliptra_rom_backdoor, caliptra_rom_size) };
        caliptra_rom_slice.copy_from_slice(&caliptra_rom_data);

        println!("Writing MCU ROM");
        let mut mcu_rom_data = vec![0; mcu_rom_size];
        mcu_rom_data[..mcu_rom.len()].clone_from_slice(mcu_rom);

        let mcu_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.mcu_rom_backdoor, mcu_rom_size) };
        mcu_rom_slice.copy_from_slice(&mcu_rom_data);

        // Set the raw unlock token hash.
        m.set_raw_unlock_token_hash(&params.ss_init_params.raw_unlock_token_hash);
        // Set the RMA or scrap PPD.
        m.set_ss_rma_or_scrap_ppd(params.ss_init_params.rma_or_scrap_ppd);
        // Setup debug intent signal if requested.
        m.set_ss_debug_intent(params.debug_intent);
        // Set BootFSM break if requested.
        m.set_bootfsm_break(params.bootfsm_break);
        // Set prod debug unlock authentication settings.
        m.wrapper
            .regs()
            .prod_debug_unlock_auth_pk_hash_reg_bank_offset
            .set(params.ss_init_params.prod_dbg_unlock_pk_hashes_offset);
        m.wrapper
            .regs()
            .num_of_prod_debug_unlock_auth_pk_hashes
            .set(params.ss_init_params.num_prod_dbg_unlock_pk_hashes);
        m.set_ss_ocp_lock(params.ocp_lock_en);

        // set the reset vector to point to the ROM backdoor
        println!("Writing MCU reset vector");
        m.wrapper
            .regs()
            .mcu_reset_vector
            .set(FPGA_MEMORY_MAP.rom_offset);

        println!("Taking subsystem out of reset");
        m.set_subsystem_reset(false);
        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaSubsystem"
    }

    // Fuses are actually written by MCU ROM, but we need to initialize the OTP
    // with the values so that they are forwarded to Caliptra. All OTP
    // initialization code should go in `init_otp()`. This function is required
    // for the HwModel trait, but is only relevant for Caliptra Core specific
    // HwModels.
    fn init_fuses(&mut self) {
        println!("Skip init_fuses(). Caliptra Core fuses are initialized by MCU ROM.");
    }

    fn boot(&mut self, boot_params: BootParams) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
    {
        // Notify MCU ROM it can start loading the fuse registers
        let gpio = &self.wrapper.regs().mci_generic_input_wires[1];
        let current = gpio.extract().get();
        gpio.set(current | 1 << 30);

        // Set soc_ifc settings before MCU ROM sets fuses
        self.soc_ifc()
            .cptra_dbg_manuf_service_reg()
            .write(|_| boot_params.initial_dbg_manuf_service_reg);

        while !self
            .mci_boot_milestones()
            .contains(McuBootMilestones::CPTRA_BOOT_GO_ASSERTED)
        {
            self.step();
        }

        // TODO: This isn't needed in the mcu-sw-model. It should be done by MCU ROM. There must be
        // something out of order that makes this necessary. Without it Caliptra ROM gets stuck in
        // the BOOT_WAIT state according to the cptra_flow_status register.
        //
        // We make this dependent on bootfsm_break, which is used to halt boot flows, e.g., for
        // entering debug unlock modes.
        if !self.bootfsm_break {
            println!("writing to cptra_bootfsm_go");
            self.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));
        }

        // Give the FPGA some time to start. If this returns too quickly some of the tests fail
        // with a kernel panic.
        let start = self.cycle_count();
        while self.cycle_count().wrapping_sub(start) < 20_000_000 {
            self.step();
            let flow_status = self.soc_ifc().cptra_flow_status().read();
            if flow_status.idevid_csr_ready() {
                // If GENERATE_IDEVID_CSR was set then we need to clear cptra_dbg_manuf_service_reg
                // once the CSR is ready to continue making progress.
                //
                // Generally the CSR should be read from the mailbox at this point, but to
                // accommodate test cases that ignore the CSR mailbox, we will ignore it here.
                self.soc_ifc().cptra_dbg_manuf_service_reg().write(|_| 0);
            }
            if flow_status.ready_for_mb_processing() {
                break;
            }
        }

        // Return here if there isn't any mutable code to load
        if boot_params.fw_image.is_none() {
            println!("Finished booting with no mutable firmware to load");
            return Ok(());
        }

        // This is the binary for:
        // L0: j L0
        // i.e., loop {}
        let mcu_fw_image = match boot_params.mcu_fw_image {
            Some(mcu_fw_image) => mcu_fw_image.to_vec(),
            None => {
                let mut mcu_fw_image = vec![0x00u8, 0x00, 0x00, 0x6f];
                mcu_fw_image.resize(256, 0);
                mcu_fw_image
            }
        };

        // TODO: support passing these into MCU ROM
        // self.soc_ifc()
        //     .cptra_wdt_cfg()
        //     .at(0)
        //     .write(|_| boot_params.wdt_timeout_cycles as u32);

        // self.soc_ifc()
        //     .cptra_wdt_cfg()
        //     .at(1)
        //     .write(|_| (boot_params.wdt_timeout_cycles >> 32) as u32);

        // if let Some(reg) = boot_params.initial_repcnt_thresh_reg {
        //     self.soc_ifc()
        //         .cptra_i_trng_entropy_config_1()
        //         .write(|_| reg);
        // }

        // if let Some(reg) = boot_params.initial_adaptp_thresh_reg {
        //     self.soc_ifc()
        //         .cptra_i_trng_entropy_config_0()
        //         .write(|_| reg);
        // }

        // TODO: support passing these into MCU ROM

        // Set up the PAUSER as valid for the mailbox (using index 0)
        // self.setup_mailbox_users(boot_params.valid_axi_user.as_slice())
        //     .map_err(ModelError::from)?;

        self.upload_firmware_rri(
            boot_params.fw_image.unwrap(),
            boot_params.soc_manifest,
            Some(&mcu_fw_image),
        )
        .unwrap();

        Ok(())
    }

    fn output(&mut self) -> &mut crate::Output {
        let cycle = self.wrapper.regs().cycle_count.get();
        self.output.sink().set_now(u64::from(cycle));
        &mut self.output
    }

    fn ready_for_fw(&self) -> bool {
        true
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }

    fn set_axi_user(&mut self, pauser: u32) {
        self.wrapper.regs().arm_user.set(pauser);
        self.wrapper.regs().lsu_user.set(pauser);
        self.wrapper.regs().ifu_user.set(pauser);
        self.wrapper.regs().dma_axi_user.set(pauser);
        self.wrapper.regs().soc_config_user.set(pauser);
        self.wrapper.regs().sram_config_user.set(pauser);
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }

    fn put_firmware_in_rri(
        &mut self,
        _firmware: &[u8],
        _soc_manifest: Option<&[u8]>,
        _mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        // ironically, we don't need to support this
        Ok(())
    }

    fn subsystem_mode(&mut self) -> bool {
        // we only support subsystem mode
        true
    }

    fn upload_firmware_rri(
        &mut self,
        firmware: &[u8],
        soc_manifest: Option<&[u8]>,
        mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        println!("Setting recovery images to BMC");
        // First add image to BMC
        self.bmc.push_recovery_image(firmware.to_vec());
        self.bmc
            .push_recovery_image(soc_manifest.unwrap_or_default().to_vec());
        self.bmc
            .push_recovery_image(mcu_firmware.unwrap_or_default().to_vec());

        while !self.i3c_target_configured() {
            self.step();
        }
        println!("Done starting MCU");

        self.i3c_controller().unwrap().configure();
        println!("Starting recovery flow (BMC)");
        self.start_recovery_bmc();
        self.step();
        println!("Finished booting");

        // Call ROM callback before informing MCU ROM it can load firmware
        if let Some(cb) = self.rom_callback.take() {
            cb(self);
        }

        // Notify MCU ROM it can start loading firmware
        let gpio = &self.wrapper.regs().mci_generic_input_wires[1];
        let current = gpio.extract().get();
        // MCU ROM will wait after reaching the mailbox for this bit before booting RT
        gpio.set(current | 1 << 31);

        // ironically, we don't need to support this
        Ok(())
    }

    fn upload_firmware(&mut self, _firmware: &[u8]) -> Result<(), ModelError> {
        Ok(())
    }

    fn warm_reset(&mut self) {
        // Toggle reset pin
        self.set_cptra_ss_rst_b(false);
        std::thread::sleep(std::time::Duration::from_micros(1));
        self.set_cptra_ss_rst_b(true);

        self.step_until(|hw| {
            hw.mci_boot_milestones()
                .contains(McuBootMilestones::CPTRA_FUSES_WRITTEN)
        });
    }

    fn write_payload_to_ss_staging_area(&mut self, payload: &[u8]) -> Result<u64, ModelError> {
        let staging_offset = 0xc00000_usize / 4; // Convert to u32 offset since mci.ptr is *mut u32
        let staging_ptr = unsafe { self.mmio.mci().unwrap().ptr.add(staging_offset) };

        // Write complete u32 chunks
        for (i, chunk) in payload.chunks(4).enumerate() {
            let u32_value = u32::from_le_bytes(chunk.try_into().unwrap());
            unsafe {
                staging_ptr.add(i).write_volatile(u32_value);
                let read_back = staging_ptr.add(i).read_volatile();
                assert_eq!(
                    read_back, u32_value,
                    "Write verification failed at offset {}",
                    i
                );
            }
        }

        let mci_base_addr: u64 = u64::from(self.soc_ifc().ss_mci_base_addr_l().read())
            | (u64::from(self.soc_ifc().ss_mci_base_addr_h().read()) << 32);

        // Return the physical address of the staging area
        Ok(mci_base_addr + 0xc00000)
    }

    /// Trigger a warm reset and advance the boot
    fn warm_reset_flow(&mut self) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
    {
        // Store non-persistent config regs set at boot
        let _dbg_manuf_service_reg = self.soc_ifc().cptra_dbg_manuf_service_reg().read();
        let _i_trng_entropy_config_1: u32 =
            self.soc_ifc().cptra_i_trng_entropy_config_1().read().into();
        let _i_trng_entropy_config_0: u32 =
            self.soc_ifc().cptra_i_trng_entropy_config_0().read().into();
        // Store mbox pausers
        let mut valid_pausers: Vec<u32> = Vec::new();
        for i in 0..caliptra_api::soc_mgr::NUM_PAUSERS {
            // Only store if locked
            if self
                .soc_ifc()
                .cptra_mbox_axi_user_lock()
                .at(i)
                .read()
                .lock()
            {
                valid_pausers.push(
                    self.soc_ifc()
                        .cptra_mbox_axi_user_lock()
                        .at(i)
                        .read()
                        .into(),
                );
            }
        }

        // Perform the warm reset
        self.warm_reset();

        // TODO: support passing these into MCU ROM

        // self.soc_ifc()
        //     .cptra_dbg_manuf_service_reg()
        //     .write(|_| dbg_manuf_service_reg);
        // self.soc_ifc()
        //     .cptra_i_trng_entropy_config_1()
        //     .write(|_| i_trng_entropy_config_1.into());
        // self.soc_ifc()
        //     .cptra_i_trng_entropy_config_0()
        //     .write(|_| i_trng_entropy_config_0.into());

        // // Re-set the valid pausers
        // self.setup_mailbox_users(valid_pausers.as_slice())
        //     .map_err(ModelError::from)?;

        self.step();

        Ok(())
    }

    fn cold_reset(&mut self) {
        self.i3c_controller()
            .unwrap()
            .controller
            .lock()
            .unwrap()
            .set_i3c_not_ready();
        self.set_subsystem_reset(true);
        std::thread::sleep(std::time::Duration::from_micros(1));
        self.init_otp(None)
            .expect("Failed to initialize OTP after cold reset");
        self.set_subsystem_reset(false);
    }

    fn fuses(&self) -> &Fuses {
        &self.fuses
    }

    fn set_fuses(&mut self, fuses: Fuses) {
        self.fuses = fuses;
    }

    fn ocp_lock_state(&mut self) -> Option<OcpLockState> {
        let mut mek = [0; 64];
        for (idx, word) in mek.chunks_exact_mut(4).enumerate() {
            let mut word = u32::mut_from_bytes(word).unwrap();
            *word = self
                .wrapper
                .regs()
                .ocp_lock_key_release_reg
                .get(idx)
                .unwrap()
                .get();
        }
        Some(OcpLockState { mek })
    }
}

pub struct FpgaRealtimeBus<'a> {
    mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}

impl FpgaRealtimeBus<'_> {
    pub fn new(mmio: *mut u32) -> Self {
        Self {
            mmio,
            phantom: Default::default(),
        }
    }

    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        let offset = match addr {
            EMULATOR_I3C_ADDR..=EMULATOR_I3C_END_ADDR => EMULATOR_I3C_ADDR,
            EMULATOR_MCI_ADDR..=EMULATOR_MCI_END_ADDR => EMULATOR_MCI_ADDR,
            0x3002_0000..0x3004_0000 => 0x3000_0000,
            _ => return None,
        };
        Some(unsafe { self.mmio.add((addr - offset) / 4) })
    }
}

impl Bus for FpgaRealtimeBus<'_> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            Ok(unsafe { ptr.read_volatile() })
        } else {
            println!("Error LoadAccessFault at address 0x{:x}", addr);
            Err(BusError::LoadAccessFault)
        }
    }

    fn write(&mut self, _size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            // TODO: support 16-bit and 8-bit writes
            unsafe { ptr.write_volatile(val) };
            Ok(())
        } else {
            Err(BusError::StoreAccessFault)
        }
    }
}

impl SocManager for ModelFpgaSubsystem {
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    type TMmio<'a>
        = BusMmio<FpgaRealtimeBus<'a>>
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.caliptra_axi_bus().unwrap())
    }

    fn delay(&mut self) {
        self.step();
    }
}

impl Drop for ModelFpgaSubsystem {
    fn drop(&mut self) {
        self.realtime_thread_exit_flag
            .store(false, Ordering::Relaxed);
        self.realtime_thread.take().unwrap().join().unwrap();
        self.i3c_controller()
            .unwrap()
            .controller
            .lock()
            .unwrap()
            .off();

        self.set_subsystem_reset(true);

        // reset the AXI bus as we leave
        self.axi_reset();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper.ptr, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.caliptra_rom_backdoor as *mut u32, CALIPTRA_ROM_MAPPING);
        self.unmap_mapping(self.mcu_rom_backdoor as *mut u32, MCU_ROM_MAPPING);
        self.unmap_mapping(self.otp_mem_backdoor as *mut u32, OTP_RAM_MAPPING);
        self.mmio.unmap(self);
    }
}

mod sensitive_mmio {
    use super::*;
    use caliptra_emu_bus::BusMmio;

    /// These MMIOs can cause a kernel crash if accessed while the subsystem is in reset.
    ///
    /// This is put in a separate module to ensure access is only done within the public functions.
    pub struct SensitiveMmio {
        enabled: bool,
        caliptra_mmio: *mut u32,
        mci: Mci,
        i3c_mmio: *mut u32,
        i3c_controller_mmio: *mut u32,
        i3c_controller: XI3CWrapper,
        otp_mmio: *mut u32,
        lc_mmio: *mut u32,
    }

    impl SensitiveMmio {
        pub fn new(args: SensitiveMmioArgs) -> Self {
            SensitiveMmio {
                enabled: false,
                caliptra_mmio: args.caliptra_mmio,
                mci: args.mci,
                i3c_mmio: args.i3c_mmio,
                i3c_controller_mmio: args.i3c_controller_mmio,
                i3c_controller: args.i3c_controller,
                otp_mmio: args.otp_mmio,
                lc_mmio: args.lc_mmio,
            }
        }

        pub fn enable(&mut self) {
            self.enabled = true;
        }

        pub fn disable(&mut self) {
            self.enabled = false;
        }

        pub fn unmap(&self, model: &ModelFpgaSubsystem) {
            model.unmap_mapping(self.caliptra_mmio, CALIPTRA_MAPPING);
            model.unmap_mapping(self.mci.ptr, MCI_MAPPING);
            model.unmap_mapping(self.i3c_mmio, I3C_TARGET_MAPPING);
            model.unmap_mapping(self.i3c_controller_mmio, I3C_CONTROLLER_MAPPING);
            model.unmap_mapping(self.otp_mmio, OTP_MAPPING);
            model.unmap_mapping(self.lc_mmio, LC_MAPPING);
        }

        pub fn caliptra_mmio(&self) -> Option<*mut u32> {
            if self.enabled {
                Some(self.caliptra_mmio)
            } else {
                None
            }
        }
        pub fn mci(&self) -> Option<Mci> {
            if self.enabled {
                Some(self.mci.clone())
            } else {
                None
            }
        }
        pub fn i3c_mmio(&self) -> Option<*mut u32> {
            if self.enabled {
                Some(self.i3c_mmio)
            } else {
                None
            }
        }
        pub fn i3c_controller_mmio(&self) -> Option<*mut u32> {
            if self.enabled {
                Some(self.i3c_controller_mmio)
            } else {
                None
            }
        }
        pub fn i3c_controller(&self) -> Option<XI3CWrapper> {
            if self.enabled {
                Some(self.i3c_controller.clone())
            } else {
                None
            }
        }
        pub fn otp_mmio(&self) -> Option<*mut u32> {
            if self.enabled {
                Some(self.otp_mmio)
            } else {
                None
            }
        }
        pub fn lc_mmio(&self) -> Option<*mut u32> {
            if self.enabled {
                Some(self.lc_mmio)
            } else {
                None
            }
        }

        pub fn i3c_core(
            &mut self,
        ) -> Option<caliptra_registers::i3ccsr::RegisterBlock<BusMmio<FpgaRealtimeBus<'_>>>>
        {
            if self.enabled {
                unsafe {
                    Some(caliptra_registers::i3ccsr::RegisterBlock::new_with_mmio(
                        crate::model_fpga_subsystem::EMULATOR_I3C_ADDR as *mut u32,
                        BusMmio::new(FpgaRealtimeBus::new(self.i3c_mmio)),
                    ))
                }
            } else {
                None
            }
        }

        pub fn caliptra_axi_bus(&mut self) -> Option<FpgaRealtimeBus<'_>> {
            if self.enabled {
                Some(FpgaRealtimeBus::new(self.caliptra_mmio))
            } else {
                None
            }
        }
    }

    pub struct SensitiveMmioArgs {
        pub caliptra_mmio: *mut u32,
        pub mci: Mci,
        pub i3c_mmio: *mut u32,
        pub i3c_controller_mmio: *mut u32,
        pub i3c_controller: XI3CWrapper,
        pub otp_mmio: *mut u32,
        pub lc_mmio: *mut u32,
    }
}
