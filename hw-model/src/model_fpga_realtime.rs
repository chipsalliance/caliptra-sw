// Licensed under the Apache-2.0 license

use std::{env, str::FromStr};

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::io::Write;
use std::time;
use uio::{UioDevice, UioError};

use crate::HwModel;
use crate::Output;

// Static variable to keep track of the handshake with the "uart" code
static mut TAG: u8 = 1;

// TODO: Make this configurable
const SOC_PAUSER: u32 = 0xffff_ffff;

fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

pub struct ModelFpgaRealtime {
    gpio: *mut u32,
    mbox: *mut u32,
    soc_ifc: *mut u32,
    output: Output,
    start_time: time::Instant,
}

impl ModelFpgaRealtime {
    fn is_ready_for_fuses(&self) -> bool {
        unsafe { (self.gpio.offset(2).read_volatile() & 0x4000_0000) != 0 }
    }
    fn set_cptra_pwrgood(&mut self, value: bool) {
        self.set_gpio(1, value);
    }
    fn set_cptra_rst_b(&mut self, value: bool) {
        self.set_gpio(0, value);
    }
    fn set_security_state(&mut self, value: u32) {
        unsafe {
            let mut val = self.gpio.read_volatile();
            val = (val & 0xFFFFFF0F) | (value << 4);
            self.gpio.write_volatile(val);
        }
    }
    fn set_uart_tag(&mut self, tag: u8) {
        unsafe {
            let mut val = self.gpio.read_volatile();
            val = (val & 0x00FFFFFF) | ((tag as u32) << 24);
            self.gpio.write_volatile(val);
        }
    }
    fn set_pauser(&mut self, pauser: u32) {
        unsafe {
            self.gpio.offset(3).write_volatile(pauser);
        }
    }
    fn set_gpio(&mut self, bit_index: u32, value: bool) {
        unsafe {
            let mut val = self.gpio.read_volatile();
            val = (val & !(1 << bit_index)) | (u32::from(value) << bit_index);
            self.gpio.write_volatile(val);
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

        let gpio = dev.map_mapping(0).map_err(fmt_uio_error)? as *mut u32;
        let mbox = dev.map_mapping(1).map_err(fmt_uio_error)? as *mut u32;
        let soc_ifc = dev.map_mapping(2).map_err(fmt_uio_error)? as *mut u32;
        let start_time = time::Instant::now();

        let mut m = Self {
            gpio,
            mbox,
            soc_ifc,
            output,
            start_time,
        };

        writeln!(m.output().logger(), "new_unbooted")?;
        // Set pwrgood and rst_b to false to boot from scratch
        m.set_cptra_pwrgood(false);
        m.set_cptra_rst_b(false);

        // Initialize SOC->Caliptra GPIO wires to 0
        unsafe { m.gpio.write_volatile(0) };

        // Set Security State signal wires
        m.set_security_state(u32::from(params.security_state));
        // Set initial tag to be non-zero
        unsafe { m.set_uart_tag(TAG) };
        // Set initial PAUSER
        m.set_pauser(SOC_PAUSER);

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
        // Temporary UART handshake to get log messages from firmware
        let generic = unsafe { self.soc_ifc.offset(0xC8 / 4).read_volatile() };

        // FW sets the generic_output register with the log character and the TAG from generic_input.
        let readtag = ((generic >> 16) & 0xFF) as u8;

        // If the TAG from FW matches what the hw-model set in the generic_input register there is new data.
        if unsafe { (TAG & 0xFF) == readtag } {
            let uartchar = generic & 0xFF;
            self.output()
                .sink()
                .push_uart_char(uartchar.try_into().unwrap());

            // Increment tag and expose on generic_input to inform uart code we have recieved the byte
            unsafe {
                TAG = TAG.wrapping_add(1);
                self.set_uart_tag(TAG);
            }
        }
    }

    fn output(&mut self) -> &mut crate::Output {
        self.output
            .sink()
            .set_now(self.start_time.elapsed().as_millis().try_into().unwrap());
        &mut self.output
    }

    fn ready_for_fw(&self) -> bool {
        unsafe { (self.gpio.offset(2).read_volatile() & 0x1000_0000) != 0 }
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
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
                0x3002_0000..=0x3002_ffff => Some(self.m.mbox.add((addr & 0xffff) / 4)),
                0x3003_0000..=0x3003_ffff => Some(self.m.soc_ifc.add((addr & 0xffff) / 4)),
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
