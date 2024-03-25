// Licensed under the Apache-2.0 license

use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::{env, str::FromStr};

use bitfield::bitfield;
use caliptra_emu_bus::{Bus, BusError, BusMmio};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use libc;
use nix;
use std::time::{self, Duration, Instant};
use uio::{UioDevice, UioError};

use crate::EtrngResponse;
use crate::Output;
use crate::{HwModel, SecurityState, TrngMode};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OpenOcdError {
    Closed,
    NotAccessible,
    WrongVersion,
}

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: usize = 0;
const CALIPTRA_MAPPING: usize = 1;

const FPGA_CLOCK_MHZ: u128 = 20;
const DEFAULT_APB_PAUSER: u32 = 0x1;

fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

// FPGA wrapper register offsets
const _FPGA_WRAPPER_GENERIC_INPUT_OFFSET: isize = 0x0000 / 4;
const _FPGA_WRAPPER_GENERIC_OUTPUT_OFFSET: isize = 0x0008 / 4;
const FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0010 / 4;
const FPGA_WRAPPER_CONTROL_OFFSET: isize = 0x0030 / 4;
const FPGA_WRAPPER_STATUS_OFFSET: isize = 0x0034 / 4;
const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x0038 / 4;
const FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
const FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET: isize = 0x1008 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET: isize = 0x100C / 4;

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires -> Caliptra
    pub struct GpioOutput(u32);
    cptra_pwrgood, set_cptra_pwrgood: 0, 0;
    cptra_rst_b, set_cptra_rst_b: 1, 1;
    debug_locked, set_debug_locked: 2, 2;
    device_lifecycle, set_device_lifecycle: 4, 3;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires <- Caliptra
    pub struct GpioInput(u32);
    cptra_error_fatal, _: 0, 0;
    cptra_error_non_fatal, _: 1, 1;
    ready_for_fuses, _: 2, 2;
    ready_for_fw, _: 3, 3;
    ready_for_runtime, _: 4, 4;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Log FIFO data
    pub struct FifoData(u32);
    log_fifo_char, _: 7, 0;
    log_fifo_valid, _: 8, 8;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Log FIFO status
    pub struct FifoStatus(u32);
    log_fifo_empty, _: 0, 0;
    log_fifo_full, _: 1, 1;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// ITRNG FIFO status
    pub struct TrngFifoStatus(u32);
    trng_fifo_empty, _: 0, 0;
    trng_fifo_full, _: 1, 1;
    trng_fifo_reset, set_trng_fifo_reset: 2, 2;
}

pub struct ModelFpgaRealtime {
    dev: UioDevice,
    wrapper: *mut u32,
    mmio: *mut u32,
    output: Output,
    start_time: time::Instant,

    realtime_thread: Option<thread::JoinHandle<()>>,
    realtime_thread_exit_flag: Arc<AtomicBool>,

    trng_mode: TrngMode,
    openocd: Option<Child>,
}

impl ModelFpgaRealtime {
    fn realtime_thread_itrng_fn(
        wrapper: *mut u32,
        exit: Arc<AtomicBool>,
        mut itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,
    ) {
        // Reset ITRNG FIFO to clear out old data
        unsafe {
            let mut trngfifosts = TrngFifoStatus(0);
            trngfifosts.set_trng_fifo_reset(1);
            wrapper
                .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                .write_volatile(trngfifosts.0);
            trngfifosts.set_trng_fifo_reset(0);
            wrapper
                .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                .write_volatile(trngfifosts.0);
        };
        // Small delay to allow reset to complete
        thread::sleep(Duration::from_millis(1));

        while !exit.load(Ordering::Relaxed) {
            // Once TRNG data is requested the FIFO will continously empty. Load at max one FIFO load at a time.
            // FPGA ITRNG FIFO is 1024 DW deep.
            for _i in 0..FPGA_ITRNG_FIFO_SIZE {
                let trngfifosts = unsafe {
                    TrngFifoStatus(
                        wrapper
                            .offset(FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET)
                            .read_volatile(),
                    )
                };
                if trngfifosts.trng_fifo_full() == 0 {
                    let mut itrng_dw = 0;
                    for i in (0..8).rev() {
                        match itrng_nibbles.next() {
                            Some(nibble) => itrng_dw += u32::from(nibble) << (4 * i),
                            None => return,
                        }
                    }
                    unsafe {
                        wrapper
                            .offset(FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET)
                            .write_volatile(itrng_dw);
                    }
                } else {
                    break;
                }
            }
            // 1 second * (20 MHz / (2^13 throttling counter)) / 8 nibbles per DW: 305 DW of data consumed in 1 second.
            let end_time = Instant::now() + Duration::from_millis(1000);
            while !exit.load(Ordering::Relaxed) && Instant::now() < end_time {
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn realtime_thread_etrng_fn(
        mmio: *mut u32,
        exit: Arc<AtomicBool>,
        mut etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
    ) {
        let soc_ifc_trng = unsafe {
            caliptra_registers::soc_ifc_trng::RegisterBlock::new_with_mmio(
                0x3003_0000 as *mut u32,
                BusMmio::new(FpgaRealtimeBus {
                    mmio,
                    phantom: Default::default(),
                }),
            )
        };

        while !exit.load(Ordering::Relaxed) {
            let trng_status = soc_ifc_trng.cptra_trng_status().read();
            if trng_status.data_req() {
                if let Some(resp) = etrng_responses.next() {
                    soc_ifc_trng.cptra_trng_data().write(&resp.data);
                    soc_ifc_trng
                        .cptra_trng_status()
                        .write(|w| w.data_wr_done(true));
                }
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn is_ready_for_fuses(&self) -> bool {
        unsafe {
            GpioInput(
                self.wrapper
                    .offset(FPGA_WRAPPER_STATUS_OFFSET)
                    .read_volatile(),
            )
            .ready_for_fuses()
                != 0
        }
    }
    fn set_cptra_pwrgood(&mut self, value: bool) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_pwrgood(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_cptra_rst_b(&mut self, value: bool) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_rst_b(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_security_state(&mut self, value: SecurityState) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_debug_locked(u32::from(value.debug_locked()));
            val.set_device_lifecycle(u32::from(value.device_lifecycle()));
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }

    fn clear_log_fifo(&mut self) {
        loop {
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            if fifodata.log_fifo_valid() == 0 {
                break;
            }
        }
    }

    fn handle_log(&mut self) {
        // Check if the FIFO is full (which probably means there was an overrun)
        let fifosts = unsafe {
            FifoStatus(
                self.wrapper
                    .offset(FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET)
                    .read_volatile(),
            )
        };
        if fifosts.log_fifo_full() != 0 {
            panic!("FPGA log FIFO overran");
        }
        // Check and empty log FIFO
        loop {
            let fifodata = unsafe {
                FifoData(
                    self.wrapper
                        .offset(FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET)
                        .read_volatile(),
                )
            };
            // Add byte to log if it is valid
            if fifodata.log_fifo_valid() != 0 {
                self.output()
                    .sink()
                    .push_uart_char(fifodata.log_fifo_char().try_into().unwrap());
            } else {
                break;
            }
        }
    }
    // UIO crate doesn't provide a way to unmap memory.
    fn unmap_mapping(&self, addr: *mut u32, mapping: usize) {
        let map_size = self.dev.map_size(mapping).unwrap();

        unsafe {
            nix::sys::mman::munmap(addr as *mut libc::c_void, map_size.into()).unwrap();
        }
    }
}

// Hack to pass *mut u32 between threads
struct SendPtr(*mut u32);
unsafe impl Send for SendPtr {}

impl HwModel for ModelFpgaRealtime {
    type TBus<'a> = FpgaRealtimeBus<'a>;

    fn new_unbooted(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);
        let uio_num = usize::from_str(&env::var("CPTRA_UIO_NUM")?)?;
        let dev = UioDevice::new(uio_num)?;

        let wrapper = dev
            .map_mapping(FPGA_WRAPPER_MAPPING)
            .map_err(fmt_uio_error)? as *mut u32;
        let mmio = dev.map_mapping(CALIPTRA_MAPPING).map_err(fmt_uio_error)? as *mut u32;

        let realtime_thread_exit_flag = Arc::new(AtomicBool::new(false));
        let realtime_thread_exit_flag2 = realtime_thread_exit_flag.clone();

        let desired_trng_mode = TrngMode::resolve(params.trng_mode);
        let realtime_thread = match desired_trng_mode {
            TrngMode::Internal => {
                let realtime_thread_wrapper = SendPtr(wrapper);
                Some(thread::spawn(move || {
                    let wrapper = realtime_thread_wrapper;
                    Self::realtime_thread_itrng_fn(
                        wrapper.0,
                        realtime_thread_exit_flag2,
                        params.itrng_nibbles,
                    )
                }))
            }
            TrngMode::External => {
                let realtime_thread_mmio = SendPtr(mmio);
                Some(thread::spawn(move || {
                    let mmio = realtime_thread_mmio;
                    Self::realtime_thread_etrng_fn(
                        mmio.0,
                        realtime_thread_exit_flag2,
                        params.etrng_responses,
                    )
                }))
            }
        };

        let mut m = Self {
            dev,
            wrapper,
            mmio,
            output,
            start_time: time::Instant::now(),

            realtime_thread,
            realtime_thread_exit_flag,

            trng_mode: desired_trng_mode,

            openocd: None,
        };

        writeln!(m.output().logger(), "new_unbooted")?;
        // Set pwrgood and rst_b to 0 to boot from scratch
        m.set_cptra_pwrgood(false);
        m.set_cptra_rst_b(false);

        // Set Security State signal wires
        m.set_security_state(params.security_state);

        // Set initial PAUSER
        m.set_apb_pauser(DEFAULT_APB_PAUSER);

        // Set deobfuscation key
        for i in 0..8 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_DEOBF_KEY_OFFSET + i)
                    .write_volatile(params.cptra_obf_key[i as usize])
            };
        }

        // Write ROM image over backdoor
        let mut rom_driver = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/caliptra-rom-backdoor")
            .unwrap();
        rom_driver.write_all(params.rom)?;
        rom_driver.sync_all()?;

        // Sometimes there's garbage in here; clean it out
        m.clear_log_fifo();

        // Update time as close to boot as possible
        m.start_time = time::Instant::now();

        // Bring Caliptra out of reset and wait for ready_for_fuses
        m.set_cptra_pwrgood(true);
        m.set_cptra_rst_b(true);
        while !m.is_ready_for_fuses() {}
        writeln!(m.output().logger(), "ready_for_fuses is high")?;

        // Checking the FPGA model needs to happen after Caliptra's registers are available.
        let fpga_trng_mode = if m.soc_ifc().cptra_hw_config().read().i_trng_en() {
            TrngMode::Internal
        } else {
            TrngMode::External
        };
        if desired_trng_mode != fpga_trng_mode {
            return Err(format!(
                "HwModel InitParams asked for trng_mode={desired_trng_mode:?}, \
                    but the FPGA was compiled with trng_mode={fpga_trng_mode:?}; \
                    try matching the test and the FPGA image."
            )
            .into());
        }

        Ok(m)
    }

    fn type_name(&self) -> &'static str {
        "ModelFpgaRealtime"
    }

    fn trng_mode(&self) -> TrngMode {
        self.trng_mode
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus {
            mmio: self.mmio,
            phantom: Default::default(),
        }
    }

    fn step(&mut self) {
        self.handle_log();
    }

    fn output(&mut self) -> &mut crate::Output {
        self.output.sink().set_now(
            (self.start_time.elapsed().as_nanos() * FPGA_CLOCK_MHZ / 1000)
                .try_into()
                .unwrap(),
        );
        &mut self.output
    }

    fn warm_reset(&mut self) {
        // Toggle reset pin
        self.set_cptra_rst_b(false);
        self.set_cptra_rst_b(true);
        // Wait for ready_for_fuses
        while !self.is_ready_for_fuses() {}
    }

    fn ready_for_fw(&self) -> bool {
        unsafe {
            GpioInput(
                self.wrapper
                    .offset(FPGA_WRAPPER_STATUS_OFFSET)
                    .read_volatile(),
            )
            .ready_for_fw()
                != 0
        }
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }

    fn set_apb_pauser(&mut self, pauser: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_PAUSER_OFFSET)
                .write_volatile(pauser);
        }
    }
}

impl ModelFpgaRealtime {
    pub fn launch_openocd(&mut self) -> Result<(), OpenOcdError> {
        let _ = Command::new("sudo")
            .arg("pkill")
            .arg("openocd")
            .spawn()
            .unwrap()
            .wait();

        let mut openocd = Command::new("sudo")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("openocd")
            .arg("--command")
            .arg(include_str!("../../hw/fpga/openocd_caliptra.txt"))
            .spawn()
            .unwrap();

        let mut child_err = BufReader::new(openocd.stderr.as_mut().unwrap());
        let mut output = String::new();
        loop {
            if 0 == child_err.read_line(&mut output).unwrap() {
                println!("openocd log returned EOF. Log: {output}");
                return Err(OpenOcdError::Closed);
            }
            if output.contains("Debug Module did not become active") {
                return Err(OpenOcdError::NotAccessible);
            }
            if output.contains("Listening on port 4444 for telnet connections") {
                break;
            }
        }
        if !output.contains("Open On-Chip Debugger 0.12.0") {
            return Err(OpenOcdError::WrongVersion);
        }

        self.openocd = Some(openocd);
        Ok(())
    }
}
impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        // Ask the realtime thread to exit and wait for it to finish
        // SAFETY: The thread is using the UIO mappings below, so it must be
        // dead before we unmap.
        // TODO: Find a safer abstraction for UIO mappings.
        self.realtime_thread_exit_flag
            .store(true, Ordering::Relaxed);
        self.realtime_thread.take().unwrap().join().unwrap();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.mmio, CALIPTRA_MAPPING);

        // Close openocd
        match &mut self.openocd {
            Some(ref mut cmd) => cmd.kill().expect("Failed to close openocd"),
            _ => (),
        }
    }
}

pub struct FpgaRealtimeBus<'a> {
    mmio: *mut u32,
    phantom: PhantomData<&'a mut ()>,
}
impl<'a> FpgaRealtimeBus<'a> {
    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        unsafe {
            match addr {
                0x3002_0000..=0x3003_ffff => Some(self.mmio.add((addr - 0x3002_0000) / 4)),
                _ => None,
            }
        }
    }
}
impl<'a> Bus for FpgaRealtimeBus<'a> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            Ok(unsafe { ptr.read_volatile() })
        } else {
            println!("Error LoadAccessFault");
            Err(BusError::LoadAccessFault)
        }
    }

    fn write(
        &mut self,
        _size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if let Some(ptr) = self.ptr_for_addr(addr) {
            // TODO: support 16-bit and 8-bit writes
            unsafe { ptr.write_volatile(val) };
            Ok(())
        } else {
            Err(BusError::StoreAccessFault)
        }
    }
}
