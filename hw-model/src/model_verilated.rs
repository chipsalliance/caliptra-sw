// Licensed under the Apache-2.0 license

use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_verilated::CaliptraVerilated;

use crate::Output;
use std::env;

// TODO: Make this configurable
const SOC_PAUSER: u32 = 0xffff_ffff;

pub struct VerilatedApbBus<'a> {
    v: &'a mut CaliptraVerilated,
}
impl<'a> Bus for VerilatedApbBus<'a> {
    fn read(&mut self, _size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 {
            return Err(caliptra_emu_bus::BusError::LoadAddrMisaligned);
        }
        Ok(self.v.apb_read_u32(SOC_PAUSER, addr))
    }

    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        if addr & 0x3 != 0 {
            return Err(caliptra_emu_bus::BusError::StoreAddrMisaligned);
        }
        if size != RvSize::Word {
            return Err(caliptra_emu_bus::BusError::StoreAccessFault);
        }
        self.v.apb_write_u32(SOC_PAUSER, addr, val);
        Ok(())
    }
}

pub struct ModelVerilated {
    v: CaliptraVerilated,

    output: Output,
    trace_enabled: bool,
}

impl ModelVerilated {
    pub fn start_tracing(&mut self, path: &str, depth: i32) {
        self.v.start_tracing(path, depth).unwrap();
    }
    pub fn stop_tracing(&mut self) {
        self.v.stop_tracing();
    }
}

impl crate::HwModel for ModelVerilated {
    type TBus<'a> = VerilatedApbBus<'a>;

    fn init(params: crate::InitParams) -> Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized,
    {
        let output = Output::new(params.log_writer);

        let output_sink = output.sink().clone();
        let generic_load_cb = Box::new(move |ch| {
            output_sink.push_uart_char(ch);
        });
        let mut v = CaliptraVerilated::with_generic_load_cb(generic_load_cb);

        v.write_rom_image(params.rom);

        let mut m = ModelVerilated {
            v,
            output,
            trace_enabled: false,
        };

        m.tracing_hint(true);

        m.v.input.cptra_pwrgood = true;
        m.v.next_cycle_high(1);

        m.v.input.cptra_rst_b = true;
        m.v.next_cycle_high(1);

        while !m.v.output.ready_for_fuses {
            m.v.next_cycle_high(1);
        }

        m.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        assert!(m.soc_ifc().cptra_fuse_wr_done().read().done());
        m.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        m.v.next_cycle_high(2);

        Ok(m)
    }

    fn apb_bus(&mut self) -> Self::TBus<'_> {
        VerilatedApbBus { v: &mut self.v }
    }

    fn step(&mut self) {
        self.v.next_cycle_high(1);
    }

    fn output(&mut self) -> &mut crate::Output {
        &mut self.output
    }

    fn tracing_hint(&mut self, enable: bool) {
        if self.trace_enabled != enable {
            self.trace_enabled = enable;
            if enable {
                if let Ok(trace_path) = env::var("CPTRA_TRACE_PATH") {
                    self.v.start_tracing(&trace_path, 99).ok();
                }
            } else {
                self.v.stop_tracing();
            }
        }
    }
}
