// Licensed under the Apache-2.0 license

#![allow(clippy::mut_from_ref)]
#![allow(dead_code)]

use crate::api_types::{DeviceLifecycle, Fuses};
use crate::bmc::Bmc;
use crate::fpga_regs::{Control, FifoData, FifoRegs, FifoStatus, ItrngFifoStatus, WrapperRegs};
use crate::otp_provision::{
    lc_generate_memory, otp_generate_lifecycle_tokens_mem, LifecycleControllerState,
    LifecycleRawTokens, LifecycleToken,
};
use crate::output::ExitStatus;
use crate::{xi3c, BootParams, Error, HwModel, InitParams, ModelError, Output, TrngMode};
use caliptra_api::SocManager;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Device, Event, EventData, RecoveryCommandCode};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_hw_model_types::{HexSlice, DEFAULT_FIELD_ENTROPY, DEFAULT_UDS_SEED};
use caliptra_image_types::FwVerificationPqcKeyType;
use std::marker::PhantomData;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use uio::{UioDevice, UioError};
use zerocopy::IntoBytes;

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

// Offsets in the OTP for fuses.
const FUSE_VENDOR_PKHASH_OFFSET: usize = 0x3f8;
const FUSE_PQC_OFFSET: usize = FUSE_VENDOR_PKHASH_OFFSET + 48;
const FUSE_LIFECYCLE_TOKENS_OFFSET: usize = 0x2d8;
const FUSE_LIFECYCLE_STATE_OFFSET: usize = 0xc80;

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
    otp_size: 0x140,

    lc_offset: 0xa404_0000,
    lc_size: 0x8c,
};

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0xcccc_cccc;
const OTP_SIZE: usize = 16384;

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

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

pub struct ModelFpgaSubsystem {
    pub devs: [UioDevice; 2],
    // mmio uio pointers
    pub wrapper: Arc<Wrapper>,
    pub caliptra_mmio: *mut u32,
    pub caliptra_rom_backdoor: *mut u8,
    pub mcu_rom_backdoor: *mut u8,
    pub otp_mem_backdoor: *mut u8,
    pub otp_init: Vec<u8>,
    pub mci: Mci,
    pub i3c_mmio: *mut u32,
    pub i3c_controller_mmio: *mut u32,
    pub i3c_controller: xi3c::Controller,
    pub otp_mmio: *mut u32,
    pub lc_mmio: *mut u32,

    pub realtime_thread: Option<thread::JoinHandle<()>>,
    pub realtime_thread_exit_flag: Arc<AtomicBool>,

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

    fn axi_reset(&mut self) {
        self.wrapper.regs().control.modify(Control::AxiReset.val(1));
        // wait a few clock cycles or we can crash the FPGA
        std::thread::sleep(std::time::Duration::from_micros(1));
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
    ) -> caliptra_registers::i3ccsr::RegisterBlock<BusMmio<FpgaRealtimeBus<'_>>> {
        unsafe {
            caliptra_registers::i3ccsr::RegisterBlock::new_with_mmio(
                EMULATOR_I3C_ADDR as *mut u32,
                BusMmio::new(FpgaRealtimeBus {
                    mmio: self.i3c_mmio,
                    phantom: Default::default(),
                }),
            )
        }
    }

    pub fn i3c_target_configured(&mut self) -> bool {
        u32::from(
            self.i3c_core()
                .stdby_ctrl_mode()
                .stby_cr_device_addr()
                .read(),
        ) != 0
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
                    .sec_fw_recovery_if()
                    .device_status_0()
                    .read()
                    .dev_status();

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
                .sec_fw_recovery_if()
                .prot_cap_0()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .prot_cap_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_2: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().prot_cap_2().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_prot_cap_3: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().prot_cap_3().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_0: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().device_id_0().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_2: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_3: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_4: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_5: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_5()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_id_reserved: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .device_id_reserved()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_status_0: {:08x}",
            u32::from(
                self.i3c_core()
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
                    .sec_fw_recovery_if()
                    .device_status_1()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_device_reset: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().device_reset().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_ctrl: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().recovery_ctrl().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_recovery_status: {:08x}",
            u32::from(
                self.i3c_core()
                    .sec_fw_recovery_if()
                    .recovery_status()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_hw_status: {:08x}",
            u32::from(self.i3c_core().sec_fw_recovery_if().hw_status().read()).swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .sec_fw_recovery_if()
                    .indirect_fifo_ctrl_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_ctrl_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_ctrl_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_0: {:08x}",
            u32::from(
                self.i3c_core()
                    .sec_fw_recovery_if()
                    .indirect_fifo_status_0()
                    .read()
            )
            .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_1: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_1()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_2: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_2()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_3: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_3()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_status_4: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_status_4()
                .read()
                .swap_bytes()
        );
        println!(
            "sec_fw_recovery_if_indirect_fifo_reserved: {:08x}",
            self.i3c_core()
                .sec_fw_recovery_if()
                .indirect_fifo_reserved()
                .read()
                .swap_bytes()
        );
    }

    fn get_i3c_primary_addr(&mut self) -> u8 {
        let reg = self
            .i3c_core()
            .stdby_ctrl_mode()
            .stby_cr_device_addr()
            .read();
        if reg.dynamic_addr_valid() {
            reg.dynamic_addr() as u8
        } else if reg.static_addr_valid() {
            reg.static_addr() as u8
        } else {
            panic!("I3C target does not have a valid address set");
        }
    }

    fn get_i3c_recovery_addr(&mut self) -> u8 {
        let reg = self
            .i3c_core()
            .stdby_ctrl_mode()
            .stby_cr_virt_device_addr()
            .read();
        if reg.virt_dynamic_addr_valid() {
            reg.virt_dynamic_addr() as u8
        } else if reg.virt_static_addr_valid() {
            reg.virt_static_addr() as u8
        } else {
            panic!("I3C virtual target does not have a valid address set");
        }
    }

    // send a recovery block write request to the I3C target
    pub fn send_i3c_write(&mut self, payload: &[u8]) {
        let target_addr = self.get_i3c_primary_addr();
        let mut cmd = xi3c::Command {
            cmd_type: 1,
            no_repeated_start: 1,
            pec: 1,
            target_addr,
            ..Default::default()
        };
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

    pub fn otp_slice(&self) -> &mut [u8] {
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

    pub fn mci_flow_status(&mut self) -> u32 {
        self.mci.regs().fw_flow_status().read()
    }

    fn caliptra_axi_bus(&mut self) -> FpgaRealtimeBus<'_> {
        FpgaRealtimeBus {
            mmio: self.caliptra_mmio,
            phantom: Default::default(),
        }
    }

    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        for (i, wire) in value.iter().copied().enumerate() {
            self.wrapper.regs().generic_input_wires[i].set(wire);
        }
    }

    fn set_itrng_divider(&mut self, divider: u32) {
        self.wrapper.regs().itrng_divisor.set(divider - 1);
    }

    fn cycle_count(&mut self) -> u64 {
        self.wrapper.regs().cycle_count.get() as u64
    }
}

impl HwModel for ModelFpgaSubsystem {
    type TBus<'a> = FpgaRealtimeBus<'a>;

    fn trng_mode(&self) -> TrngMode {
        TrngMode::Internal
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus {
            mmio: self.caliptra_mmio,
            phantom: Default::default(),
        }
    }

    fn step(&mut self) {
        self.handle_log();
        self.bmc_step();
    }

    /// Create a model, and boot it to the point where CPU execution can
    /// occur. This includes programming the fuses, initializing the
    /// boot_fsm state machine, and (optionally) uploading firmware.
    fn new(init_params: InitParams, boot_params: BootParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let init_params_summary = init_params.summary();

        let mut hw: Self = HwModel::new_unbooted(init_params)?;
        println!(
            "Using hardware-model {} trng={:?}",
            hw.type_name(),
            hw.trng_mode(),
        );
        println!("{init_params_summary:#?}");

        hw.boot(boot_params)?;

        Ok(hw)
    }

    fn new_unbooted(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        match params.trng_mode {
            Some(TrngMode::External) => {
                return Err("External TRNG mode is not supported in ModelFpgaSubsystem".into());
            }
            _ => {}
        }
        let mcu_rom =
            match params.mcu_rom {
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

        let realtime_thread = Some(std::thread::spawn(move || {
            Self::realtime_thread_itrng_fn(
                realtime_wrapper,
                realtime_thread_exit_flag2,
                params.itrng_nibbles,
            )
        }));

        let i3c_controller = xi3c::Controller::new(i3c_controller_mmio);

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
            caliptra_mmio,
            caliptra_rom_backdoor,
            mcu_rom_backdoor,
            otp_mem_backdoor,
            mci: Mci { ptr: mci_ptr },
            i3c_mmio,
            i3c_controller_mmio,
            i3c_controller,
            otp_mmio,
            lc_mmio,

            otp_init: vec![],
            realtime_thread,
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
        };

        println!("AXI reset");
        m.axi_reset();

        // Set generic input wires.
        let input_wires = [0, (!params.uds_granularity_64 as u32) << 31];
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

        // Clear the generic input wires in case they were left in a non-zero state.
        m.set_generic_input_wires(&[0, 0]);

        println!("Putting subsystem into reset");
        m.set_subsystem_reset(true);

        let mut otp_data = vec![0; OTP_SIZE];

        if !m.otp_init.is_empty() {
            // write the initial contents of the OTP memory
            println!("Initializing OTP with initialized data");
            if m.otp_init.len() > otp_data.len() {
                Err(format!(
                    "OTP initialization data is larger than OTP memory {} > {}",
                    m.otp_init.len(),
                    otp_data.len(),
                ))?;
            }
            otp_data[..m.otp_init.len()].copy_from_slice(&m.otp_init);
        }

        let lc_state = match params.security_state.device_lifecycle() {
            DeviceLifecycle::Unprovisioned => LifecycleControllerState::TestUnlocked0,
            DeviceLifecycle::Manufacturing => LifecycleControllerState::Dev,
            DeviceLifecycle::Reserved2 => LifecycleControllerState::Raw,
            DeviceLifecycle::Production => LifecycleControllerState::Prod,
        };
        println!("Setting lifecycle controller state to {}", lc_state);
        let mem = lc_generate_memory(lc_state, 1)?;
        let offset = FUSE_LIFECYCLE_STATE_OFFSET;
        otp_data[offset..offset + mem.len()].copy_from_slice(&mem);

        let tokens = &DEFAULT_LIFECYCLE_RAW_TOKENS;
        let mem = otp_generate_lifecycle_tokens_mem(tokens)?;
        let offset = FUSE_LIFECYCLE_TOKENS_OFFSET;
        otp_data[offset..offset + mem.len()].copy_from_slice(&mem);

        let otp_mem = m.otp_slice();
        otp_mem.copy_from_slice(&otp_data);

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
        mcu_rom_data[..mcu_rom.len()].clone_from_slice(&mcu_rom);

        let mcu_rom_slice =
            unsafe { core::slice::from_raw_parts_mut(m.mcu_rom_backdoor, mcu_rom_size) };
        mcu_rom_slice.copy_from_slice(&mcu_rom_data);

        // set the reset vector to point to the ROM backdoor
        println!("Writing MCU reset vector");
        m.wrapper
            .regs()
            .mcu_reset_vector
            .set(FPGA_MEMORY_MAP.rom_offset);
        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaSubsystem"
    }

    // Fuses are actually written by MCU ROM, but we need to initialize the OTP
    // with the values so that they are forwarded to Caliptra.
    fn init_fuses(&mut self, fuses: &Fuses) {
        let vendor_pk_hash = fuses.vendor_pk_hash.as_bytes();
        println!(
            "Setting vendor public key hash to {:x?}",
            HexSlice(vendor_pk_hash)
        );

        // inefficient but works around bus errors on the FPGA when doing unaligned writes to AXI
        let mut otp_mem = self.otp_slice().to_vec();
        otp_mem[FUSE_VENDOR_PKHASH_OFFSET..FUSE_VENDOR_PKHASH_OFFSET + vendor_pk_hash.len()]
            .copy_from_slice(vendor_pk_hash);

        let vendor_pqc_type = FwVerificationPqcKeyType::from_u8(fuses.fuse_pqc_key_type as u8)
            .unwrap_or(FwVerificationPqcKeyType::LMS);
        println!(
            "Setting vendor public key pqc type to {:x?}",
            vendor_pqc_type
        );
        let val = match vendor_pqc_type {
            FwVerificationPqcKeyType::MLDSA => 0,
            FwVerificationPqcKeyType::LMS => 1,
        };
        otp_mem[FUSE_PQC_OFFSET] = val;

        self.otp_slice().copy_from_slice(&otp_mem);
    }

    fn boot(&mut self, boot_params: BootParams) -> Result<(), Box<dyn Error>>
    where
        Self: Sized,
    {
        HwModel::init_fuses(self, &boot_params.fuses);

        println!("Taking subsystem out of reset");
        self.set_subsystem_reset(false);

        while !self.i3c_target_configured() {}
        println!("Done starting MCU");

        // TODO: support passing these into MCU ROM
        // self.soc_ifc()
        //     .cptra_wdt_cfg()
        //     .at(0)
        //     .write(|_| boot_params.wdt_timeout_cycles as u32);

        // self.soc_ifc()
        //     .cptra_wdt_cfg()
        //     .at(1)
        //     .write(|_| (boot_params.wdt_timeout_cycles >> 32) as u32);

        // TODO: do we need to support these in MCU ROM?
        // self.soc_ifc()
        //     .cptra_dbg_manuf_service_reg()
        //     .write(|_| boot_params.initial_dbg_manuf_service_reg);

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

        // TODO: This isn't needed in the mcu-sw-model. It should be done by MCU ROM. There must be
        // something out of order that makes this necessary. Without it Caliptra ROM gets stuck in
        // the BOOT_WAIT state according to the cptra_flow_status register.
        println!("writing to cptra_bootfsm_go");
        self.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        self.step();

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

        println!("Setting recovery images to BMC");
        self.bmc
            .push_recovery_image(boot_params.fw_image.map(|s| s.to_vec()).unwrap_or_default());
        self.bmc.push_recovery_image(
            boot_params
                .soc_manifest
                .map(|s| s.to_vec())
                .unwrap_or_default(),
        );
        self.bmc.push_recovery_image(mcu_fw_image);

        let mut xi3c_configured = false;
        // TODO(zhalvorsen): Instead of waiting a fixed number of steps this should only wait until
        // it is done or timeout.
        for _ in 0..1_000_000 {
            if !xi3c_configured && self.i3c_target_configured() {
                xi3c_configured = true;
                println!("I3C target configured");
                self.configure_i3c_controller();
                println!("Starting recovery flow (BMC)");
                self.start_recovery_bmc();
            }
            self.step();
        }
        println!("Finished booting");

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
}

pub struct FpgaRealtimeBus<'a> {
    mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}

impl FpgaRealtimeBus<'_> {
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
        BusMmio::new(self.caliptra_axi_bus())
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
        self.i3c_controller.off();

        self.set_subsystem_reset(true);

        // reset the AXI bus as we leave
        self.axi_reset();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper.ptr, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.caliptra_mmio, CALIPTRA_MAPPING);
        self.unmap_mapping(self.caliptra_rom_backdoor as *mut u32, CALIPTRA_ROM_MAPPING);
        self.unmap_mapping(self.mcu_rom_backdoor as *mut u32, MCU_ROM_MAPPING);
        self.unmap_mapping(self.otp_mem_backdoor as *mut u32, OTP_RAM_MAPPING);
        self.unmap_mapping(self.mci.ptr, MCI_MAPPING);
        self.unmap_mapping(self.i3c_mmio, I3C_TARGET_MAPPING);
        self.unmap_mapping(self.i3c_controller_mmio, I3C_CONTROLLER_MAPPING);
        self.unmap_mapping(self.otp_mmio, OTP_MAPPING);
        self.unmap_mapping(self.lc_mmio, LC_MAPPING);
    }
}
