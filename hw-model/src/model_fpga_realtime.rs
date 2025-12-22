// Licensed under the Apache-2.0 license

use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::{env, slice, str::FromStr};

use bitfield::bitfield;
use caliptra_emu_bus::{Bus, BusError, BusMmio, Event};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use libc;
use nix;
use std::time::{Duration, Instant};
use uio::{UioDevice, UioError};

use crate::EtrngResponse;
use crate::Fuses;
use crate::ModelError;
use crate::Output;
use crate::{HwModel, SecurityState, SocManager, TrngMode};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum OpenOcdError {
    Closed,
    CaliptraNotAccessible,
    VeerNotAccessible,
    WrongVersion,
}

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: usize = 0;
const CALIPTRA_MAPPING: usize = 1;
const ROM_MAPPING: usize = 2;

// Set to core_clk cycles per ITRNG sample.
const ITRNG_DIVISOR: u32 = 400;
const DEFAULT_AXI_PAUSER: u32 = 0x1;

pub(crate) fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

// ITRNG FIFO stores 1024 DW and outputs 4 bits at a time to Caliptra.
const FPGA_ITRNG_FIFO_SIZE: usize = 1024;

// FPGA wrapper register offsets
const FPGA_WRAPPER_MAGIC_OFFSET: isize = 0x0000 / 4;
const FPGA_WRAPPER_VERSION_OFFSET: isize = 0x0004 / 4;
const FPGA_WRAPPER_CONTROL_OFFSET: isize = 0x0008 / 4;
const FPGA_WRAPPER_STATUS_OFFSET: isize = 0x000C / 4;
const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x0010 / 4;
const FPGA_WRAPPER_ITRNG_DIV_OFFSET: isize = 0x0014 / 4;
const FPGA_WRAPPER_CYCLE_COUNT_OFFSET: isize = 0x0018 / 4;
const FPGA_WRAPPER_GENERIC_INPUT_OFFSET: isize = 0x0030 / 4;
const _FPGA_WRAPPER_GENERIC_OUTPUT_OFFSET: isize = 0x0038 / 4;
// Secrets
const FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0040 / 4;
const FPGA_WRAPPER_CSR_HMAC_KEY_OFFSET: isize = 0x0060 / 4;
const FPGA_WRAPPER_OBF_UDS_SEED_OFFSET: isize = 0x00A0 / 4;
const FPGA_WRAPPER_OBF_FIELD_ENTROPY_OFFSET: isize = 0x00E0 / 4;
// FIFOs
const FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
const FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_DATA_OFFSET: isize = 0x1008 / 4;
const FPGA_WRAPPER_ITRNG_FIFO_STATUS_OFFSET: isize = 0x100C / 4;

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires -> Caliptra
    pub struct WrapperControl(u32);
    cptra_pwrgood, set_cptra_pwrgood: 0, 0;
    cptra_rst_b, set_cptra_rst_b: 1, 1;
    cptra_obf_uds_seed_vld, set_cptra_obf_uds_seed_vld: 2, 2;
    cptra_obf_field_entropy_vld, set_cptra_obf_field_entropy_vld: 3, 3;
    debug_locked, set_debug_locked: 4, 4;
    device_lifecycle, set_device_lifecycle: 6, 5;
    bootfsm_brkpoint, set_bootfsm_brkpoint: 7, 7;
    scan_mode, set_scan_mode: 8, 8;

    rsvd_ss_debug_intent, set_rsvd_ss_debug_intent: 16, 16;
    rsvd_i3c_axi_user_id_filtering, set_rsvd_i3c_axi_user_id_filtering: 17, 17;
    rsvd_ocp_lock_en, set_rsvd_ocp_lock_en: 18, 18;
    rsvd_lc_allow_rma_or_scrap_on_ppd, set_rsvd_lc_allow_rma_or_scrap_on_ppd: 19, 19;
    rsvd_fips_zeroization_ppd, set_rsvd_fips_zeroization_ppd: 20, 20;

    axi_reset, set_axi_reset: 31, 31;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires <- Caliptra
    pub struct WrapperStatus(u32);
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
    fuses: Fuses,

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
                    for i in 0..8 {
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

    fn axi_reset(&mut self) {
        unsafe {
            let mut val = WrapperControl(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_axi_reset(1);
            // wait a few clock cycles or we can crash the FPGA
            std::thread::sleep(std::time::Duration::from_micros(1));
        }
    }

    fn is_ready_for_fuses(&self) -> bool {
        unsafe {
            WrapperStatus(
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
            let mut val = WrapperControl(
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
            let mut val = WrapperControl(
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
            let mut val = WrapperControl(
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
    fn set_secrets_valid(&mut self, value: bool) {
        unsafe {
            let mut val = WrapperControl(
                self.wrapper
                    .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_obf_uds_seed_vld(value as u32);
            val.set_cptra_obf_field_entropy_vld(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_CONTROL_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_generic_input_wires(&mut self, value: &[u32; 2]) {
        unsafe {
            for i in 0..2 {
                self.wrapper
                    .offset(FPGA_WRAPPER_GENERIC_INPUT_OFFSET + i)
                    .write_volatile(value[i as usize]);
            }
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

    fn set_itrng_divider(&mut self, divider: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_ITRNG_DIV_OFFSET)
                .write_volatile(divider - 1);
        }
    }
}

// Hack to pass *mut u32 between threads
struct SendPtr(*mut u32);
unsafe impl Send for SendPtr {}

impl SocManager for ModelFpgaRealtime {
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;

    const MAX_WAIT_CYCLES: u32 = 20_000_000;

    type TMmio<'a> = BusMmio<FpgaRealtimeBus<'a>>;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        BusMmio::new(self.apb_bus())
    }

    fn delay(&mut self) {
        self.step();
    }
}
impl HwModel for ModelFpgaRealtime {
    type TBus<'a> = FpgaRealtimeBus<'a>;

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus {
            mmio: self.mmio,
            phantom: Default::default(),
        }
    }

    fn step(&mut self) {
        // The FPGA can't be stopped.
        // Never stop never stopping.
        self.handle_log();
    }

    fn step_until_boot_status(
        &mut self,
        expected_status_u32: u32,
        ignore_intermediate_status: bool,
    ) {
        // We need to check the cycle count from the FPGA, and do so quickly
        // as possible since the ARM host core is slow.

        // do an immediate check
        let initial_boot_status_u32: u32 = self.soc_ifc().cptra_boot_status().read();
        if initial_boot_status_u32 == expected_status_u32 {
            return;
        }

        // Since the boot takes about 30M cycles, we know something is wrong if
        // we're stuck at the same state for that duration.
        const MAX_WAIT_CYCLES: u32 = 30_000_000;
        // only check the log every 4096 cycles for performance reasons
        const LOG_CYCLES: usize = 0x1000;

        let start_cycle_count = self.cycle_count();
        for i in 0..usize::MAX {
            let actual_status_u32 = self.soc_ifc().cptra_boot_status().read();
            if expected_status_u32 == actual_status_u32 {
                break;
            }

            if !ignore_intermediate_status && actual_status_u32 != initial_boot_status_u32 {
                let cycle_count = self.cycle_count().wrapping_sub(start_cycle_count);
                panic!(
                    "{cycle_count} Expected the next boot_status to be \
                    ({expected_status_u32}), but status changed from \
                    {initial_boot_status_u32} to {actual_status_u32})"
                );
            }

            // only handle the log sometimes so that we don't miss a state transition
            if i & (LOG_CYCLES - 1) == 0 {
                self.handle_log();
            }
            let cycle_count = self.cycle_count().wrapping_sub(start_cycle_count);
            if cycle_count >= MAX_WAIT_CYCLES {
                panic!(
                    "Expected boot_status to be \
                    ({expected_status_u32}), but was stuck at ({actual_status_u32})"
                );
            }
        }
    }

    fn new_unbooted(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);
        let uio_num = usize::from_str(
            &env::var("CPTRA_UIO_NUM").expect("Set CPTRA_UIO_NUM when using the FPGA"),
        )?;
        // This locks the device, and so acts as a test mutex so that only one test can run at a time.
        let dev = UioDevice::blocking_new(uio_num)
            .expect("UIO driver not found. Run \"sudo ./hw/fpga/setup_fpga.sh\"");

        let wrapper = dev
            .map_mapping(FPGA_WRAPPER_MAPPING)
            .map_err(fmt_uio_error)? as *mut u32;
        let mmio = dev.map_mapping(CALIPTRA_MAPPING).map_err(fmt_uio_error)? as *mut u32;
        let rom = dev.map_mapping(ROM_MAPPING).map_err(fmt_uio_error)? as *mut u8;
        let rom_size = dev.map_size(ROM_MAPPING).map_err(fmt_uio_error)?;

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

        let uds_seed = params.fuses.uds_seed;
        let field_entropy = params.fuses.field_entropy;

        let mut m = Self {
            dev,
            wrapper,
            mmio,
            output,
            fuses: params.fuses,

            realtime_thread,
            realtime_thread_exit_flag,

            trng_mode: desired_trng_mode,

            openocd: None,
        };

        // Check if the FPGA image is valid
        if 0x52545043 == unsafe { wrapper.offset(FPGA_WRAPPER_MAGIC_OFFSET).read_volatile() } {
            let fpga_version = unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_VERSION_OFFSET)
                    .read_volatile()
            };
            writeln!(m.output().logger(), "FPGA built from {fpga_version:x}")?;
        } else {
            panic!("FPGA image invalid");
        }

        // Set pwrgood and rst_b to 0 to boot from scratch
        m.set_cptra_pwrgood(false);
        m.set_cptra_rst_b(false);

        writeln!(m.output().logger(), "new_unbooted")?;

        println!("AXI reset");
        m.axi_reset();

        // Set generic input wires.
        let input_wires = [(!params.uds_fuse_row_granularity_64 as u32) << 31, 0];
        m.set_generic_input_wires(&input_wires);

        // Set Security State signal wires
        m.set_security_state(params.security_state);

        // Set initial PAUSER
        m.set_axi_user(DEFAULT_AXI_PAUSER);

        // Set divisor for ITRNG throttling
        m.set_itrng_divider(ITRNG_DIVISOR);

        // Set deobfuscation key
        for i in 0..8 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_DEOBF_KEY_OFFSET + i)
                    .write_volatile(params.cptra_obf_key[i as usize])
            };
        }

        // Set the CSR HMAC key
        for i in 0..16 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_CSR_HMAC_KEY_OFFSET + i)
                    .write_volatile(params.csr_hmac_key[i as usize])
            };
        }

        // Set the UDS Seed
        for i in 0..16 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_OBF_UDS_SEED_OFFSET + i)
                    .write_volatile(uds_seed[i as usize])
            };
        }

        // Set the FE Seed
        for i in 0..8 {
            unsafe {
                m.wrapper
                    .offset(FPGA_WRAPPER_OBF_FIELD_ENTROPY_OFFSET + i)
                    .write_volatile(field_entropy[i as usize])
            };
        }

        // Currently not using strap UDS and FE
        m.set_secrets_valid(false);

        // Write ROM image over backdoor
        writeln!(m.output().logger(), "Writing ROM")?;

        let mut rom_data = vec![0; rom_size];
        rom_data[..params.rom.len()].clone_from_slice(params.rom);

        let rom_slice = unsafe { slice::from_raw_parts_mut(rom, rom_size) };
        rom_slice.copy_from_slice(&rom_data);

        // Sometimes there's garbage in here; clean it out
        m.clear_log_fifo();

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

    fn output(&mut self) -> &mut crate::Output {
        let cycle = self.cycle_count();
        self.output.sink().set_now(u64::from(cycle));
        &mut self.output
    }

    fn warm_reset(&mut self) {
        // Toggle reset pin
        self.set_cptra_rst_b(false);
        self.set_cptra_rst_b(true);
        // Wait for ready_for_fuses
        while !self.is_ready_for_fuses() {}
    }

    fn cold_reset(&mut self) {
        // Toggle reset and pwrgood
        self.set_cptra_rst_b(false);
        self.set_cptra_pwrgood(false);
        self.set_cptra_pwrgood(true);
        self.set_cptra_rst_b(true);
        // Wait for ready_for_fuses
        while !self.is_ready_for_fuses() {}
    }

    fn ready_for_fw(&self) -> bool {
        unsafe {
            WrapperStatus(
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

    fn set_axi_user(&mut self, pauser: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_PAUSER_OFFSET)
                .write_volatile(pauser);
        }
    }

    fn put_firmware_in_rri(
        &mut self,
        _firmware: &[u8],
        _soc_manifest: Option<&[u8]>,
        _mcu_firmware: Option<&[u8]>,
    ) -> Result<(), ModelError> {
        todo!()
    }

    fn events_from_caliptra(&mut self) -> Vec<Event> {
        todo!()
    }

    fn events_to_caliptra(&mut self) -> mpsc::Sender<Event> {
        todo!()
    }

    fn write_payload_to_ss_staging_area(&mut self, _payload: &[u8]) -> Result<u64, ModelError> {
        Err(ModelError::SubsystemSramError)
    }

    fn read_payload_from_ss_staging_area(&mut self, _len: usize) -> Result<Vec<u8>, ModelError> {
        Err(ModelError::SubsystemSramError)
    }

    fn fuses(&self) -> &Fuses {
        &self.fuses
    }

    fn set_fuses(&mut self, fuses: Fuses) {
        self.fuses = fuses;
    }
}

impl ModelFpgaRealtime {
    fn cycle_count(&self) -> u32 {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_CYCLE_COUNT_OFFSET)
                .read_volatile()
        }
    }

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
            if output.contains("OpenOCD setup finished") {
                break;
            }
        }
        if !output.contains("Open On-Chip Debugger 0.12.0") {
            return Err(OpenOcdError::WrongVersion);
        }
        if output.contains("Caliptra not accessible") {
            return Err(OpenOcdError::CaliptraNotAccessible);
        }
        if output.contains("Core not accessible") {
            return Err(OpenOcdError::VeerNotAccessible);
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

        // reset the AXI bus as we leave
        self.axi_reset();

        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.mmio, CALIPTRA_MAPPING);
        self.unmap_mapping(self.mmio, ROM_MAPPING);

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
                0x3002_0000..=0x3003_ffff => Some(self.mmio.add((addr - 0x3000_0000) / 4)),
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
