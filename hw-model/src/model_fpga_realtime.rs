use std::{env, str::FromStr};

use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::io::Write;
use uio::{UioDevice, UioError};

use crate::HwModel;

fn fmt_uio_error(err: UioError) -> String {
    format!("{err:?}")
}

pub struct ModelFpgaRealtime {
    _dev: UioDevice,
    gpio: *mut u32,
    mbox: *mut u32,
    soc_ifc: *mut u32,
}

impl ModelFpgaRealtime {
    fn is_ready_for_fuses(&self) -> bool {
        unsafe { (self.gpio.offset(2).read_volatile() & 0x8000_0000) != 0 }
    }
    fn set_cptra_pwrgood(&mut self, value: bool) {
        self.set_gpio(1, value);
    }
    fn set_cptra_rst_b(&mut self, value: bool) {
        self.set_gpio(0, value);
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

    fn new_unbooted(_params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let uio_num = usize::from_str(&env::var("CPTRA_UIO_NUM")?)?;
        let dev = UioDevice::new(uio_num)?;

        // TODO: Figure out how to load params.security_state into the
        // caliptra_top wires (using GPIO?)

        // TODO: Figure out how to load the ROM image from params.rom into the
        // FPGA block ram.

        let gpio = dev.map_mapping(0).map_err(fmt_uio_error)? as *mut u32;
        let mbox = dev.map_mapping(1).map_err(fmt_uio_error)? as *mut u32;
        let soc_ifc = dev.map_mapping(2).map_err(fmt_uio_error)? as *mut u32;

        let mut m = Self {
            _dev: dev,
            gpio,
            mbox,
            soc_ifc,
        };
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
        // Do nothing; model is realtime so the test has no power to affect the
        // passage of time.
    }

    fn output(&mut self) -> &mut crate::Output {
        todo!();
    }

    fn ready_for_fw(&self) -> bool {
        // TODO: Read from GPIO register (not sure what the index is)
        todo!()
    }

    fn tracing_hint(&mut self, _enable: bool) {
        // Do nothing; we don't support tracing yet
    }
}

pub struct FpgaRealtimeBus<'a> {
    m: &'a mut ModelFpgaRealtime,
}
impl<'a> FpgaRealtimeBus<'a> {
    fn ptr_for_addr(&self, addr: RvAddr) -> Option<*mut u32> {
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
            // TODO: support 16-bit and 8-bit reads
            Ok(unsafe { ptr.read_volatile() })
        } else {
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
