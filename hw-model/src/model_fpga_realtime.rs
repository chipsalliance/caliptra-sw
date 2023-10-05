// Licensed under the Apache-2.0 license

use std::{env, str::FromStr};

use bitfield::bitfield;
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use libc;
use nix;
use std::io::Write;
use std::time;
use uio::{UioDevice, UioError};

use crate::EtrngResponse;
use crate::HwModel;
use crate::Output;

// UIO mapping indices
const FPGA_WRAPPER_MAPPING: usize = 0;
const CALIPTRA_MAPPING: usize = 1;

fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

// FPGA wrapper register offsets
const FPGA_WRAPPER_OUTPUT_OFFSET: isize = 0x0000 / 4;
const FPGA_WRAPPER_INPUT_OFFSET: isize = 0x0008 / 4;
const FPGA_WRAPPER_PAUSER_OFFSET: isize = 0x000C / 4;
const FPGA_WRAPPER_DEOBF_KEY_OFFSET: isize = 0x0020 / 4;
const FPGA_WRAPPER_LOG_FIFO_DATA_OFFSET: isize = 0x1000 / 4;
const FPGA_WRAPPER_LOG_FIFO_STATUS_OFFSET: isize = 0x1004 / 4;

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires -> Caliptra
    pub struct GpioOutput(u32);
    cptra_rst_b, set_cptra_rst_b: 0, 0;
    cptra_pwrgood, set_cptra_pwrgood: 1, 1;
    security_state, set_security_state: 6, 4;
}

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    /// Wrapper wires <- Caliptra
    pub struct GpioInput(u32);
    cptra_error_fatal, _: 26, 26;
    cptra_error_non_fatal, _: 27, 27;
    ready_for_fw, _: 28, 28;
    ready_for_runtime, _: 29, 29;
    ready_for_fuses, _: 30, 30;
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

pub struct ModelFpgaRealtime {
    dev: UioDevice,
    wrapper: *mut u32,
    mmio: *mut u32,
    output: Output,
    start_time: time::Instant,

    etrng_responses: Box<dyn Iterator<Item = EtrngResponse>>,
    etrng_response: Option<[u32; 12]>,
    etrng_waiting_for_req_to_clear: bool,
}

impl ModelFpgaRealtime {
    fn is_ready_for_fuses(&self) -> bool {
        unsafe {
            GpioInput(
                self.wrapper
                    .offset(FPGA_WRAPPER_INPUT_OFFSET)
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
                    .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_pwrgood(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_cptra_rst_b(&mut self, value: bool) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                    .read_volatile(),
            );
            val.set_cptra_rst_b(value as u32);
            self.wrapper
                .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_security_state(&mut self, value: u32) {
        unsafe {
            let mut val = GpioOutput(
                self.wrapper
                    .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                    .read_volatile(),
            );
            val.set_security_state(value);
            self.wrapper
                .offset(FPGA_WRAPPER_OUTPUT_OFFSET)
                .write_volatile(val.0);
        }
    }
    fn set_pauser(&mut self, pauser: u32) {
        unsafe {
            self.wrapper
                .offset(FPGA_WRAPPER_PAUSER_OFFSET)
                .write_volatile(pauser);
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

    fn handle_etrng(&mut self) {
        let trng_status = self.soc_ifc_trng().cptra_trng_status().read();
        if self.etrng_waiting_for_req_to_clear && !trng_status.data_req() {
            self.etrng_waiting_for_req_to_clear = false;
        }
        if trng_status.data_req() && !self.etrng_waiting_for_req_to_clear {
            if self.etrng_response.is_none() {
                if let Some(response) = self.etrng_responses.next() {
                    self.etrng_response = Some(response.data);
                }
            }
            if let Some(_) = &mut self.etrng_response {
                self.etrng_waiting_for_req_to_clear = true;
                let etrng_response = self.etrng_response.take().unwrap();
                self.soc_ifc_trng().cptra_trng_data().write(&etrng_response);
                self.soc_ifc_trng()
                    .cptra_trng_status()
                    .write(|w| w.data_wr_done(true));
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
        let start_time = time::Instant::now();

        let mut m = Self {
            dev,
            wrapper,
            mmio,
            output,
            start_time,

            etrng_responses: params.etrng_responses,
            etrng_response: None,
            etrng_waiting_for_req_to_clear: false,
        };

        writeln!(m.output().logger(), "new_unbooted")?;
        // Set pwrgood and rst_b to 0 to boot from scratch
        m.set_cptra_pwrgood(false);
        m.set_cptra_rst_b(false);

        // Set Security State signal wires
        m.set_security_state(u32::from(params.security_state));

        // Set initial PAUSER
        m.set_pauser(params.soc_apb_pauser);

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

        // Bring Caliptra out of reset and wait for ready_for_fuses
        m.set_cptra_pwrgood(true);
        m.set_cptra_rst_b(true);
        while !m.is_ready_for_fuses() {}
        writeln!(m.output().logger(), "ready_for_fuses is high")?;

        Ok(m)
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        FpgaRealtimeBus { m: self }
    }

    fn step(&mut self) {
        self.handle_log();

        // FPGA only supports ETRNG for now and needs to be checked frequently.
        self.handle_etrng();
    }

    fn output(&mut self) -> &mut crate::Output {
        self.output
            .sink()
            .set_now(self.start_time.elapsed().as_millis().try_into().unwrap());
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
                    .offset(FPGA_WRAPPER_INPUT_OFFSET)
                    .read_volatile(),
            )
            .ready_for_fw()
                != 0
        }
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }
}
impl Drop for ModelFpgaRealtime {
    fn drop(&mut self) {
        // Unmap UIO memory space so that the file lock is released
        self.unmap_mapping(self.wrapper, FPGA_WRAPPER_MAPPING);
        self.unmap_mapping(self.mmio, CALIPTRA_MAPPING);
    }
}

pub struct FpgaRealtimeBus<'a> {
    m: &'a mut ModelFpgaRealtime,
}
impl<'a> FpgaRealtimeBus<'a> {
    fn ptr_for_addr(&mut self, addr: RvAddr) -> Option<*mut u32> {
        let addr = addr as usize;
        unsafe {
            match addr {
                0x3002_0000..=0x3003_ffff => Some(self.m.mmio.add((addr - 0x3002_0000) / 4)),
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
