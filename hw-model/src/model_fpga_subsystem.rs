// Licensed under the Apache-2.0 license

#![allow(clippy::mut_from_ref)]

use crate::bmc::Bmc;
use crate::fpga_regs::{Control, FifoData, FifoRegs, FifoStatus, ItrngFifoStatus, WrapperRegs};
use crate::otp_provision::{lc_generate_memory, otp_generate_lifecycle_tokens_mem};
use crate::output::ExitStatus;
use crate::{xi3c, HwModel, InitParams, Output};
use anyhow::{anyhow, bail, Error, Result};
use caliptra_api::SocManager;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Device, Event, EventData, RecoveryCommandCode};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::{HexSlice, DEFAULT_FIELD_ENTROPY, DEFAULT_UDS_SEED};
use caliptra_image_types::FwVerificationPqcKeyType;
// use caliptra_registers::i3c::bits::{DeviceStatus0, StbyCrDeviceAddr, StbyCrVirtDeviceAddr};
// use caliptra_registers::mci::bits::Go::Go;
// use caliptra_registers::{fuses, i3c};
use std::io::Write;
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uio::{UioDevice, UioError};

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

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0xcccc_cccc;
const OTP_SIZE: usize = 16384;

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

/// Unhashed token, suitable for doing lifecycle transitions.
#[derive(Clone, Copy)]
pub struct LifecycleToken(pub [u8; 16]);

impl From<[u8; 16]> for LifecycleToken {
    fn from(value: [u8; 16]) -> Self {
        LifecycleToken(value)
    }
}

impl From<LifecycleToken> for [u8; 16] {
    fn from(value: LifecycleToken) -> Self {
        value.0
    }
}

/// Raw tokens
pub struct LifecycleRawTokens {
    pub test_unlock: [LifecycleToken; 7],
    pub manuf: LifecycleToken,
    pub manuf_to_prod: LifecycleToken,
    pub prod_to_prod_end: LifecycleToken,
    pub rma: LifecycleToken,
}

impl From<[u8; 16]> for LifecycleHashedToken {
    fn from(value: [u8; 16]) -> Self {
        LifecycleHashedToken(value)
    }
}

impl From<LifecycleHashedToken> for [u8; 16] {
    fn from(value: LifecycleHashedToken) -> Self {
        value.0
    }
}

/// Hashed tokens to be burned into the OTP for lifecycle transitions.
pub struct LifecycleHashedTokens {
    pub test_unlock: [LifecycleHashedToken; 7],
    pub manuf: LifecycleHashedToken,
    pub manuf_to_prod: LifecycleHashedToken,
    pub prod_to_prod_end: LifecycleHashedToken,
    pub rma: LifecycleHashedToken,
}

/// Hashed token, suitable for burning into the OTP.
#[derive(Clone, Copy)]
pub struct LifecycleHashedToken(pub [u8; 16]);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleControllerState {
    Raw = 0,
    TestUnlocked0 = 1,
    TestLocked0 = 2,
    TestUnlocked1 = 3,
    TestLocked1 = 4,
    TestUnlocked2 = 5,
    TestLocked2 = 6,
    TestUnlocked3 = 7,
    TestLocked3 = 8,
    TestUnlocked4 = 9,
    TestLocked4 = 10,
    TestUnlocked5 = 11,
    TestLocked5 = 12,
    TestUnlocked6 = 13,
    TestLocked6 = 14,
    TestUnlocked7 = 15,
    Dev = 16,
    Prod = 17,
    ProdEnd = 18,
    Rma = 19,
    Scrap = 20,
}

impl core::fmt::Display for LifecycleControllerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LifecycleControllerState::Raw => write!(f, "raw"),
            LifecycleControllerState::TestUnlocked0 => write!(f, "test_unlocked0"),
            LifecycleControllerState::TestLocked0 => write!(f, "test_locked0"),
            LifecycleControllerState::TestUnlocked1 => write!(f, "test_unlocked1"),
            LifecycleControllerState::TestLocked1 => write!(f, "test_locked1"),
            LifecycleControllerState::TestUnlocked2 => write!(f, "test_unlocked2"),
            LifecycleControllerState::TestLocked2 => write!(f, "test_locked2"),
            LifecycleControllerState::TestUnlocked3 => write!(f, "test_unlocked3"),
            LifecycleControllerState::TestLocked3 => write!(f, "test_locked3"),
            LifecycleControllerState::TestUnlocked4 => write!(f, "test_unlocked4"),
            LifecycleControllerState::TestLocked4 => write!(f, "test_locked4"),
            LifecycleControllerState::TestUnlocked5 => write!(f, "test_unlocked5"),
            LifecycleControllerState::TestLocked5 => write!(f, "test_locked5"),
            LifecycleControllerState::TestUnlocked6 => write!(f, "test_unlocked6"),
            LifecycleControllerState::TestLocked6 => write!(f, "test_locked6"),
            LifecycleControllerState::TestUnlocked7 => write!(f, "test_unlocked7"),
            LifecycleControllerState::Dev => write!(f, "dev"),
            LifecycleControllerState::Prod => write!(f, "prod"),
            LifecycleControllerState::ProdEnd => write!(f, "prod_end"),
            LifecycleControllerState::Rma => write!(f, "rma"),
            LifecycleControllerState::Scrap => write!(f, "scrap"),
        }
    }
}

impl core::str::FromStr for LifecycleControllerState {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(LifecycleControllerState::Raw),
            "test_unlocked0" => Ok(LifecycleControllerState::TestUnlocked0),
            "test_locked0" => Ok(LifecycleControllerState::TestLocked0),
            "test_unlocked1" => Ok(LifecycleControllerState::TestUnlocked1),
            "test_locked1" => Ok(LifecycleControllerState::TestLocked1),
            "test_unlocked2" => Ok(LifecycleControllerState::TestUnlocked2),
            "test_locked2" => Ok(LifecycleControllerState::TestLocked2),
            "test_unlocked3" => Ok(LifecycleControllerState::TestUnlocked3),
            "test_locked3" => Ok(LifecycleControllerState::TestLocked3),
            "test_unlocked4" => Ok(LifecycleControllerState::TestUnlocked4),
            "test_locked4" => Ok(LifecycleControllerState::TestLocked4),
            "test_unlocked5" => Ok(LifecycleControllerState::TestUnlocked5),
            "test_locked5" => Ok(LifecycleControllerState::TestLocked5),
            "test_unlocked6" => Ok(LifecycleControllerState::TestUnlocked6),
            "test_locked6" => Ok(LifecycleControllerState::TestLocked6),
            "test_unlocked7" => Ok(LifecycleControllerState::TestUnlocked7),
            "dev" | "manuf" | "manufacturing" => Ok(LifecycleControllerState::Dev),
            "production" | "prod" => Ok(LifecycleControllerState::Prod),
            "prod_end" => Ok(LifecycleControllerState::ProdEnd),
            "rma" => Ok(LifecycleControllerState::Rma),
            "scrap" => Ok(LifecycleControllerState::Scrap),
            _ => Err("Invalid lifecycle state"),
        }
    }
}

impl From<LifecycleControllerState> for u8 {
    fn from(value: LifecycleControllerState) -> Self {
        match value {
            LifecycleControllerState::Raw => 0,
            LifecycleControllerState::TestUnlocked0 => 1,
            LifecycleControllerState::TestLocked0 => 2,
            LifecycleControllerState::TestUnlocked1 => 3,
            LifecycleControllerState::TestLocked1 => 4,
            LifecycleControllerState::TestUnlocked2 => 5,
            LifecycleControllerState::TestLocked2 => 6,
            LifecycleControllerState::TestUnlocked3 => 7,
            LifecycleControllerState::TestLocked3 => 8,
            LifecycleControllerState::TestUnlocked4 => 9,
            LifecycleControllerState::TestLocked4 => 10,
            LifecycleControllerState::TestUnlocked5 => 11,
            LifecycleControllerState::TestLocked5 => 12,
            LifecycleControllerState::TestUnlocked6 => 13,
            LifecycleControllerState::TestLocked6 => 14,
            LifecycleControllerState::TestUnlocked7 => 15,
            LifecycleControllerState::Dev => 16,
            LifecycleControllerState::Prod => 17,
            LifecycleControllerState::ProdEnd => 18,
            LifecycleControllerState::Rma => 19,
            LifecycleControllerState::Scrap => 20,
        }
    }
}

impl From<u8> for LifecycleControllerState {
    fn from(value: u8) -> Self {
        match value {
            1 => LifecycleControllerState::TestUnlocked0,
            2 => LifecycleControllerState::TestLocked0,
            3 => LifecycleControllerState::TestUnlocked1,
            4 => LifecycleControllerState::TestLocked1,
            5 => LifecycleControllerState::TestUnlocked2,
            6 => LifecycleControllerState::TestLocked2,
            7 => LifecycleControllerState::TestUnlocked3,
            8 => LifecycleControllerState::TestLocked3,
            9 => LifecycleControllerState::TestUnlocked4,
            10 => LifecycleControllerState::TestLocked4,
            11 => LifecycleControllerState::TestUnlocked5,
            12 => LifecycleControllerState::TestLocked5,
            13 => LifecycleControllerState::TestUnlocked6,
            14 => LifecycleControllerState::TestLocked6,
            15 => LifecycleControllerState::TestUnlocked7,
            16 => LifecycleControllerState::Dev,
            17 => LifecycleControllerState::Prod,
            18 => LifecycleControllerState::ProdEnd,
            19 => LifecycleControllerState::Rma,
            20 => LifecycleControllerState::Scrap,
            _ => LifecycleControllerState::Raw,
        }
    }
}

impl From<u32> for LifecycleControllerState {
    fn from(value: u32) -> Self {
        ((value & 0x1f) as u8).into()
    }
}

// This is a random number, but should be kept in sync with what is the default value in the FPGA ROM.
const DEFAULT_LIFECYCLE_RAW_TOKEN: LifecycleToken =
    LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());

const DEFAULT_LIFECYCLE_RAW_TOKENS: LifecycleRawTokens = LifecycleRawTokens {
    test_unlock: [DEFAULT_LIFECYCLE_RAW_TOKEN; 7],
    manuf: DEFAULT_LIFECYCLE_RAW_TOKEN,
    manuf_to_prod: DEFAULT_LIFECYCLE_RAW_TOKEN,
    prod_to_prod_end: DEFAULT_LIFECYCLE_RAW_TOKEN,
    rma: DEFAULT_LIFECYCLE_RAW_TOKEN,
};

fn fmt_uio_error(err: UioError) -> Error {
    anyhow!("{err:?}")
}

struct Wrapper {
    ptr: *mut u32,
}

impl Wrapper {
    fn regs(&self) -> &mut WrapperRegs {
        unsafe { &mut *(self.ptr as *mut WrapperRegs) }
    }
    fn fifo_regs(&self) -> &mut FifoRegs {
        unsafe { &mut *(self.ptr.offset(0x1000 / 4) as *mut FifoRegs) }
    }
}
unsafe impl Send for Wrapper {}
unsafe impl Sync for Wrapper {}

struct Mci {
    ptr: *mut u32,
}

impl Mci {
    fn regs(&self) -> &mut registers_generated::mci::regs::Mci {
        unsafe { &mut *(self.ptr as *mut registers_generated::mci::regs::Mci) }
    }
}

struct CaliptraMmio {
    ptr: *mut u32,
}

impl CaliptraMmio {
    #[allow(unused)]
    fn mbox(&self) -> &mut registers_generated::mbox::regs::Mbox {
        unsafe {
            &mut *(self.ptr.offset(0x2_0000 / 4) as *mut registers_generated::mbox::regs::Mbox)
        }
    }
    #[allow(unused)]
    fn soc(&self) -> &mut registers_generated::soc::regs::Soc {
        unsafe { &mut *(self.ptr.offset(0x3_0000 / 4) as *mut registers_generated::soc::regs::Soc) }
    }
}

pub struct ModelFpgaRealtime {
    devs: [UioDevice; 2],
    // mmio uio pointers
    wrapper: Arc<Wrapper>,
    caliptra_mmio: CaliptraMmio,
    caliptra_rom_backdoor: *mut u8,
    mcu_rom_backdoor: *mut u8,
    otp_mem_backdoor: *mut u8,
    otp_init: Vec<u8>,
    mci: Mci,
    i3c_mmio: *mut u32,
    i3c_controller_mmio: *mut u32,
    i3c_controller: xi3c::Controller,

    realtime_thread: Option<thread::JoinHandle<()>>,
    realtime_thread_exit_flag: Arc<AtomicBool>,

    output: Output,
    recovery_started: bool,
    bmc: Bmc,
    from_bmc: mpsc::Receiver<Event>,
    to_bmc: mpsc::Sender<Event>,
    recovery_fifo_blocks: Vec<Vec<u8>>,
    recovery_ctrl_len: usize,
    recovery_ctrl_written: bool,
    bmc_step_counter: usize,
    i3c_target: &'static i3c::regs::I3c,
    blocks_sent: usize,
    openocd: Option<TcpStream>,
}

impl ModelFpgaRealtime {
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
    fn set_subsystem_reset(&mut self, reset: bool) {
        self.wrapper.regs().control.modify(
            Control::CptraSsRstB.val((!reset) as u32) + Control::CptraPwrgood.val((!reset) as u32),
        );
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
        if self.output().exit_requested() {
            println!("Exiting firmware request");
            let code = match self.output().exit_status() {
                Some(ExitStatus::Passed) => 0,
                Some(ExitStatus::Failed) => 1,
                None => 0,
            };
            exit(code);
        }
    }

    // UIO crate doesn't provide a way to unmap memory.
    fn unmap_mapping(&self, addr: *mut u32, mapping: (usize, usize)) {
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

    pub fn i3c_core(&mut self) -> &i3c::regs::I3c {
        unsafe { &*(self.i3c_mmio as *const i3c::regs::I3c) }
    }

    pub fn i3c_target_configured(&mut self) -> bool {
        let i3c_target = unsafe { &*(self.i3c_mmio as *const i3c::regs::I3c) };
        i3c_target.stdby_ctrl_mode_stby_cr_device_addr.get() != 0
    }

    pub fn configure_i3c_controller(&mut self) {
        println!("I3C controller initializing");
        println!(
            "XI3C HW version = {:x}",
            self.i3c_controller.regs().version.get()
        );
        let xi3c_config = xi3c::Config {
            device_id: 0,
            base_address: self.i3c_controller_mmio,
            input_clock_hz: 199_999_000,
            rw_fifo_depth: 16,
            wr_threshold: 12,
            device_count: 1,
            ibi_capable: true,
            hj_capable: false,
            entdaa_enable: true,
            known_static_addrs: vec![0x3a, 0x3b],
        };

        self.i3c_controller.set_s_clk(199_999_000, 12_500_000, 1);
        self.i3c_controller
            .cfg_initialize(&xi3c_config, self.i3c_controller_mmio as usize)
            .unwrap();
        println!("I3C controller finished initializing");
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
        if self.bmc_step_counter % 128 == 0 && !self.recovery_fifo_blocks.is_empty() {
            if !self.recovery_ctrl_written {
                let status = self
                    .i3c_core()
                    .sec_fw_recovery_if_device_status_0
                    .read(DeviceStatus0::DevStatus);

                if status != 3 && self.bmc_step_counter % 65536 == 0 {
                    println!("Waiting for device status to be 3, currently: {}", status);
                    return;
                }

                let len = ((self.recovery_ctrl_len / 4) as u32).to_le_bytes();
                let mut ctrl = vec![0, 1];
                ctrl.extend_from_slice(&len);

                println!("Writing Indirect fifo ctrl: {:x?}", ctrl);
                self.recovery_block_write_request(RecoveryCommandCode::IndirectFifoCtrl, &ctrl);

                let reported_len = self
                    .i3c_core()
                    .sec_fw_recovery_if_indirect_fifo_ctrl_1
                    .get();

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
                .recovery_block_read_request(RecoveryCommandCode::IndirectFifoStatus)
                .expect("Device should response to indirect fifo status read request");
            let empty = fifo_status[0] & 1 == 1;
            // while empty send
            if empty {
                // fifo is empty, send a block
                let chunk = self.recovery_fifo_blocks.pop().unwrap();
                self.blocks_sent += 1;
                self.recovery_block_write_request(RecoveryCommandCode::IndirectFifoData, &chunk);
            }
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
                // let fifo_status =
                //     self.recovery_block_read_request(RecoveryCommandCode::IndirectFifoStatus);

                let mut image = image.clone();
                while image.len() % 256 != 0 {
                    image.push(0);
                }
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
                .sec_fw_recovery_if_prot_cap_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_prot_cap_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_2: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_prot_cap_2
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_3: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_prot_cap_3
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_0: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_2: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_2
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_3: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_3
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_4: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_4
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_5: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_5
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_reserved: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_id_reserved
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_0: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_status_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_status_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_reset: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_device_reset
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_ctrl: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_recovery_ctrl
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_status: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_recovery_status
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_hw_status: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_hw_status
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_0: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_ctrl_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_ctrl_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_0: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_status_0
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_status_1
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_2: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_status_2
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_3: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_status_3
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_4: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_status_4
                .get()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_reserved: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if_indirect_fifo_reserved
                .get()
                .swap_bytes()
        );
    }

    fn get_i3c_primary_addr(&mut self) -> u8 {
        let reg = self
            .i3c_core()
            .stdby_ctrl_mode_stby_cr_device_addr
            .extract();
        if reg.is_set(StbyCrDeviceAddr::DynamicAddrValid) {
            reg.read(StbyCrDeviceAddr::DynamicAddr) as u8
        } else if reg.is_set(StbyCrDeviceAddr::StaticAddrValid) {
            reg.read(StbyCrDeviceAddr::StaticAddr) as u8
        } else {
            panic!("I3C target does not have a valid address set");
        }
    }

    fn get_i3c_recovery_addr(&mut self) -> u8 {
        let reg = self
            .i3c_core()
            .stdby_ctrl_mode_stby_cr_virt_device_addr
            .extract();
        if reg.is_set(StbyCrVirtDeviceAddr::VirtDynamicAddrValid) {
            reg.read(StbyCrVirtDeviceAddr::VirtDynamicAddr) as u8
        } else if reg.is_set(StbyCrVirtDeviceAddr::VirtStaticAddrValid) {
            reg.read(StbyCrVirtDeviceAddr::VirtStaticAddr) as u8
        } else {
            panic!("I3C target does not have a valid address set");
        }
    }

    // send a recovery block write request to the I3C target
    pub fn send_i3c_write(&mut self, payload: &[u8]) {
        let target_addr = self.get_i3c_primary_addr();
        println!("I3C addr = {:x}", target_addr);
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            pec: 1,
            target_addr,
            ..Default::default()
        };
        println!("TTI status: {:x}", self.i3c_core().tti_status.get());
        println!(
            "TTI interrupt enable: {:x}",
            self.i3c_core().tti_interrupt_enable.get()
        );
        println!(
            "TTI interrupt status: {:x}",
            self.i3c_core().tti_interrupt_status.get()
        );
        match self
            .i3c_controller
            .master_send_polled(&mut cmd, payload, payload.len() as u16)
        {
            Ok(_) => {
                println!("Acknowledge received");
            }
            Err(e) => {
                println!("Failed to ack write message sent to target: {:x}", e);
            }
        }

        println!("TTI status: {:x}", self.i3c_core().tti_status.get());
        println!(
            "TTI interrupt enable: {:x}",
            self.i3c_core().tti_interrupt_enable.get()
        );
        println!(
            "TTI interrupt status: {:x}",
            self.i3c_core().tti_interrupt_status.get()
        );
    }

    // send a recovery block read request to the I3C target
    fn recovery_block_read_request(&mut self, command: RecoveryCommandCode) -> Option<Vec<u8>> {
        // per the recovery spec, this maps to a private write and private read

        let target_addr = self.get_i3c_recovery_addr();

        // First we write the recovery command code for the block we want
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 0, // we want the next command (read) to be Sr
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = Self::command_code_to_u8(command);

        if self
            .i3c_controller
            .master_send_polled(&mut cmd, &[recovery_command_code], 1)
            .is_err()
        {
            return None;
        }

        // then we send a private read for the minimum length
        let len_range = Self::command_code_to_len(command);
        cmd.target_addr = target_addr;
        cmd.no_repeated_start = 0;
        cmd.tid = 0;
        cmd.pec = 0;
        cmd.cmd_type = 1;

        self.i3c_controller
            .master_recv(&mut cmd, len_range.0 + 2)
            .expect("Failed to receive ack from target");

        // read in the length, lsb then msb
        let resp = self
            .i3c_controller
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

        let target_addr = self.get_i3c_recovery_addr();
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            pec: 1,
            target_addr,
            ..Default::default()
        };

        let recovery_command_code = Self::command_code_to_u8(command);

        let mut data = vec![recovery_command_code];
        data.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        data.extend_from_slice(payload);

        assert!(
            self.i3c_controller
                .master_send_polled(&mut cmd, &data, data.len() as u16)
                .is_ok(),
            "Failed to ack write message sent to target"
        );
        // println!("Acknowledge received");
    }

    fn otp_slice(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.otp_mem_backdoor, OTP_SIZE) }
    }

    pub fn print_otp_memory(&self) {
        let otp = self.otp_slice();
        for (i, oi) in otp.iter().copied().enumerate() {
            if oi != 0 {
                println!("OTP mem: {:03x}: {:02x}", i, oi);
            }
        }
    }

    pub fn open_openocd(&mut self, port: u16) -> Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let stream = TcpStream::connect(addr)?;
        self.openocd = Some(stream);
        Ok(())
    }

    pub fn close_openocd(&mut self) {
        self.openocd.take();
    }

    pub fn set_uds_req(&mut self) -> Result<()> {
        let Some(mut socket) = self.openocd.take() else {
            bail!("openocd socket is not open");
        };

        socket.write_all("riscv.cpu riscv dmi_write 0x70 4\n".as_bytes())?;

        self.openocd = Some(socket);
        Ok(())
    }

    pub fn set_bootfsm_go(&mut self) -> Result<()> {
        let Some(mut socket) = self.openocd.take() else {
            bail!("openocd socket is not open");
        };

        socket.write_all("riscv.cpu riscv dmi_write 0x61 1\n".as_bytes())?;

        self.openocd = Some(socket);
        Ok(())
    }

    pub fn mci_flow_status(&mut self) -> u32 {
        self.mci.regs().mci_reg_fw_flow_status.get()
    }

    fn caliptra_axi_bus(&mut self) -> FpgaRealtimeBus<'_> {
        FpgaRealtimeBus {
            mmio: self.caliptra_mmio.ptr,
            phantom: Default::default(),
        }
    }
}

impl McuHwModel for ModelFpgaRealtime {
    fn step(&mut self) {
        self.handle_log();
        self.bmc_step();
    }

    fn new_unbooted(params: InitParams) -> Result<Self>
    where
        Self: Sized,
    {
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
        let _lc_mmio = devs[LC_MAPPING.0]
            .map_mapping(LC_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;
        let _otp_mmio = devs[OTP_MAPPING.0]
            .map_mapping(OTP_MAPPING.1)
            .map_err(fmt_uio_error)? as *mut u32;

        let realtime_thread_exit_flag = Arc::new(AtomicBool::new(true));
        let realtime_thread_exit_flag2 = realtime_thread_exit_flag.clone();
        let realtime_wrapper = wrapper.clone();
        let i3c_target = unsafe { &*(i3c_mmio as *const i3c::regs::I3c) };

        let realtime_thread = Some(std::thread::spawn(move || {
            Self::realtime_thread_itrng_fn(
                realtime_wrapper,
                realtime_thread_exit_flag2,
                params.itrng_nibbles,
            )
        }));

        let i3c_controller = xi3c::Controller::new(i3c_controller_mmio);

        // For now, we copy the runtime directly into the SRAM
        let mut mcu_fw = params.mcu_firmware.to_vec();
        while mcu_fw.len() % 8 != 0 {
            mcu_fw.push(0);
        }

        let (caliptra_cpu_event_sender, from_bmc) = mpsc::channel();
        let (to_bmc, caliptra_cpu_event_recv) = mpsc::channel();

        // these aren't used
        let (mcu_cpu_event_sender, mcu_cpu_event_recv) = mpsc::channel();

        // This is a fake BMC that runs the recovery flow as a series of events for recovery block reads and writes.
        let mut bmc = Bmc::new(
            caliptra_cpu_event_sender,
            caliptra_cpu_event_recv,
            mcu_cpu_event_sender,
            mcu_cpu_event_recv,
        );
        bmc.push_recovery_image(params.caliptra_firmware.to_vec());
        bmc.push_recovery_image(params.soc_manifest.to_vec());
        bmc.push_recovery_image(params.mcu_firmware.to_vec());

        let mut m = Self {
            devs,
            wrapper,
            caliptra_mmio: CaliptraMmio { ptr: caliptra_mmio },
            caliptra_rom_backdoor,
            mcu_rom_backdoor,
            otp_mem_backdoor,
            mci: Mci { ptr: mci_ptr },
            i3c_mmio,
            i3c_controller_mmio,
            i3c_controller,
            otp_init: params.otp_memory.map(|m| m.to_vec()).unwrap_or_default(),
            realtime_thread,
            realtime_thread_exit_flag,

            output,
            recovery_started: false,
            bmc,
            from_bmc,
            to_bmc,
            recovery_fifo_blocks: vec![],
            bmc_step_counter: 0,
            i3c_target,
            blocks_sent: 0,
            recovery_ctrl_written: false,
            recovery_ctrl_len: 0,
            openocd: None,
        };

        // Set generic input wires.
        let input_wires = [0, (!params.uds_granularity_32 as u32) << 31];
        m.set_generic_input_wires(&input_wires);

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

        // Set the UDS Seed
        for (i, udsi) in DEFAULT_UDS_SEED.iter().copied().enumerate() {
            m.wrapper.regs().cptra_obf_uds_seed[i].set(udsi);
        }

        // Set the FE Seed
        for (i, fei) in DEFAULT_FIELD_ENTROPY.iter().copied().enumerate() {
            m.wrapper.regs().cptra_obf_field_entropy[i].set(fei);
        }

        // Currently not using strap UDS and FE
        m.set_secrets_valid(false);

        m.set_bootfsm_break(params.bootfsm_break);

        // Clear the generic input wires in case they were left in a non-zero state.
        m.set_generic_input_wires(&[0, 0]);
        m.set_mcu_generic_input_wires(&[0, 0]);

        // if params.uds_program_req {
        //     // notify MCU that we want to run the UDS provisioning flow
        //     m.set_mcu_generic_input_wires(&[1, 0]);
        // }

        println!("Putting subsystem into reset");
        m.set_subsystem_reset(true);

        println!("Clearing OTP memory");
        let otp_mem = m.otp_slice();
        otp_mem.fill(0);

        if !m.otp_init.is_empty() {
            // write the initial contents of the OTP memory
            println!("Initializing OTP with initialized data");
            if m.otp_init.len() > otp_mem.len() {
                bail!(
                    "OTP initialization data is larger than OTP memory {} > {}",
                    m.otp_init.len(),
                    otp_mem.len()
                );
            }
            otp_mem[..m.otp_init.len()].copy_from_slice(&m.otp_init);
        }

        if let Some(state) = params.lifecycle_controller_state {
            println!("Setting lifecycle controller state to {}", state);
            let mem = lc_generate_memory(state, 1)?;
            // TODO: use the autogenerated offset when we update caliptra-ss
            let offset = 4008;
            otp_mem[offset..offset + mem.len()].copy_from_slice(&mem);
            // otp_mem[fuses::LIFE_CYCLE_BYTE_OFFSET..fuses::LIFE_CYCLE_BYTE_OFFSET + mem.len()]
            //     .copy_from_slice(&mem);

            let tokens = params
                .lifecycle_tokens
                .as_ref()
                .unwrap_or(&DEFAULT_LIFECYCLE_RAW_TOKENS);
            let mem = otp_generate_lifecycle_tokens_mem(tokens)?;
            // TODO: use the autogenerated offset when we update caliptra-ss
            let offset = 1184;
            otp_mem[offset..offset + mem.len()].copy_from_slice(&mem);

            // otp_mem[fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET
            //     ..fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_OFFSET
            //         + fuses::SECRET_LC_TRANSITION_PARTITION_BYTE_SIZE]
            //     .copy_from_slice(&mem);
        }

        if let Some(vendor_pk_hash) = params.vendor_pk_hash.as_ref() {
            println!(
                "Setting vendor public key hash to {:x?}",
                HexSlice(vendor_pk_hash)
            );
            // swap endianness to match expected hardware format
            let len = vendor_pk_hash.len();
            let mut vendor_pk_hash = vendor_pk_hash.to_vec();
            for i in (0..len).step_by(4) {
                vendor_pk_hash[i..i + 4].reverse();
            }
            let otp_mem = m.otp_slice();
            let offset = fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET;
            otp_mem[offset..offset + len].copy_from_slice(&vendor_pk_hash);
        }
        let vendor_pqc_type = params
            .vendor_pqc_type
            .unwrap_or(FwVerificationPqcKeyType::LMS);
        println!(
            "Setting vendor public key pqc type to {:x?}",
            vendor_pqc_type
        );
        let val = match vendor_pqc_type {
            FwVerificationPqcKeyType::MLDSA => 0,
            FwVerificationPqcKeyType::LMS => 1,
        };
        let otp_mem = m.otp_slice();
        let offset = fuses::VENDOR_HASHES_MANUF_PARTITION_BYTE_OFFSET + 48;
        otp_mem[offset] = val;

        println!("Clearing fifo");
        // Sometimes there's garbage in here; clean it out
        m.clear_logs();

        println!("new_unbooted");

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        println!("AXI user written {:x}", DEFAULT_AXI_PAUSER);

        // Write ROM images over backdoors
        // ensure that they are 8-byte aligned to write to AXI
        let mut caliptra_rom_data = params.caliptra_rom.to_vec();
        while caliptra_rom_data.len() % 8 != 0 {
            caliptra_rom_data.push(0);
        }

        let mut mcu_rom_data = vec![0; mcu_rom_size];
        mcu_rom_data[..params.mcu_rom.len()].clone_from_slice(params.mcu_rom);

        // copy the ROM data
        let caliptra_rom_slice = unsafe {
            core::slice::from_raw_parts_mut(m.caliptra_rom_backdoor, caliptra_rom_data.len())
        };
        println!("Writing Caliptra ROM ({} bytes)", caliptra_rom_data.len());
        caliptra_rom_slice.copy_from_slice(&caliptra_rom_data);
        println!("Writing MCU ROM");
        let mcu_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.mcu_rom_backdoor, mcu_rom_size) };
        mcu_rom_slice.copy_from_slice(&mcu_rom_data);

        // set the reset vector to point to the ROM backdoor
        println!("Writing MCU reset vector");
        m.wrapper
            .regs()
            .mcu_reset_vector
            .set(mcu_config_fpga::FPGA_MEMORY_MAP.rom_offset);

        println!("Taking subsystem out of reset");
        m.set_subsystem_reset(false);

        // println!(
        //     "Mode {}",
        //     if (m.caliptra_mmio.soc().cptra_hw_config.get() >> 5) & 1 == 1 {
        //         "subsystem"
        //     } else {
        //         "passive"
        //     }
        // );

        // TODO: remove this when we can finish subsystem/active mode
        // println!("Writing MCU firmware to SRAM");
        // // For now, we copy the runtime directly into the SRAM
        // let mut fw_data = params.mcu_firmware.to_vec();
        // while fw_data.len() % 8 != 0 {
        //     fw_data.push(0);
        // }
        // // TODO: remove this offset 0x80 and add 128 bytes of padding to the beginning of the firmware
        // // as this is going to fail when we use the DMA controller
        // let sram_slice = unsafe {
        //     core::slice::from_raw_parts_mut(m.mcu_sram_backdoor.offset(0x80), fw_data.len())
        // };
        // sram_slice.copy_from_slice(&fw_data);

        println!("Done starting MCU");
        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaRealtime"
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

    fn set_caliptra_boot_go(&mut self, go: bool) {
        self.mci
            .regs()
            .mci_reg_cptra_boot_go
            .write(Go.val(go as u32));
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        self.wrapper.regs().itrng_divisor.set(divider - 1);
    }

    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.wrapper.regs().generic_input_wires[i].set(wire);
        }
    }

    fn set_mcu_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.wrapper.regs().mci_generic_input_wires[i].set(wire);
        }
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }

    fn cycle_count(&mut self) -> u64 {
        self.wrapper.regs().cycle_count.get() as u64
    }

    fn save_otp_memory(&self, path: &Path) -> Result<()> {
        let s = crate::vmem::write_otp_vmem_data(self.otp_slice())?;
        Ok(std::fs::write(path, s.as_bytes())?)
    }

    fn caliptra_soc_manager(&mut self) -> impl SocManager {
        self
    }
}

pub struct FpgaRealtimeBus<'a> {
    mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}

impl FpgaRealtimeBus<'_> {
    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        unsafe {
            match addr {
                0x3002_0000..=0x3003_ffff => Some(self.mmio.add((addr - 0x3000_0000) / 4)),
                _ => None,
            }
        }
    }
}

impl Bus for FpgaRealtimeBus<'_> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            Ok(unsafe { ptr.read_volatile() })
        } else {
            println!("Error LoadAccessFault");
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

impl SocManager for &mut ModelFpgaRealtime {
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    type TMmio<'a>
        = BusMmio<FpgaRealtimeBus<'a>>
    where
        Self: 'a;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.caliptra_axi_bus())
    }

    fn delay(&mut self) {
        self.step();
    }
}

impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        self.realtime_thread_exit_flag
            .store(false, Ordering::Relaxed);
        self.realtime_thread.take().unwrap().join().unwrap();
        self.close_openocd();
        self.i3c_controller.off();

        self.set_generic_input_wires(&[0, 0]);
        self.set_mcu_generic_input_wires(&[0, 0]);

        // ensure that we put the I3C target into a state where we will reset it properly
        self.i3c_target.stdby_ctrl_mode_stby_cr_device_addr.set(0);
        self.set_subsystem_reset(true);

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper.ptr, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.caliptra_mmio.ptr, CALIPTRA_MAPPING);
        self.unmap_mapping(self.caliptra_rom_backdoor as *mut u32, CALIPTRA_ROM_MAPPING);
        self.unmap_mapping(self.mcu_rom_backdoor as *mut u32, MCU_ROM_MAPPING);
        self.unmap_mapping(self.otp_mem_backdoor as *mut u32, OTP_RAM_MAPPING);
        self.unmap_mapping(self.mci.ptr, MCI_MAPPING);
        self.unmap_mapping(self.i3c_mmio, I3C_TARGET_MAPPING);
        self.unmap_mapping(self.i3c_controller_mmio, I3C_CONTROLLER_MAPPING);
    }
}

#[cfg(test)]
mod test {
    use crate::{DefaultHwModel, InitParams, McuHwModel};
    use mcu_builder::FirmwareBinaries;
    use mcu_rom_common::McuRomBootStatus;

    #[test]
    fn test_new_unbooted() {
        let firmware_bundle = FirmwareBinaries::from_env().unwrap();
        let mut model = DefaultHwModel::new_unbooted(InitParams {
            caliptra_rom: &firmware_bundle.caliptra_rom,
            caliptra_firmware: &firmware_bundle.caliptra_fw,
            mcu_rom: &firmware_bundle.mcu_rom,
            mcu_firmware: &firmware_bundle.mcu_runtime,
            soc_manifest: &firmware_bundle.soc_manifest,
            active_mode: true,
            ..Default::default()
        })
        .unwrap();

        model.step_until(|m| m.mci_flow_status() == u32::from(McuRomBootStatus::I3cInitialized));
    }
}
