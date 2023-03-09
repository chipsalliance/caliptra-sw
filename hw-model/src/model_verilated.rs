// Licensed under the Apache-2.0 license

use std::sync::mpsc;

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

    generic_load_rx: mpsc::Receiver<u8>,
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
        let (generic_load_tx, generic_load_rx) = mpsc::channel();
        let generic_load_cb = Box::new(move |ch| {
            let _ = generic_load_tx.send(ch);
        });
        let mut v = CaliptraVerilated::with_generic_load_cb(generic_load_cb);

        v.write_rom_image(params.rom);

        v.input.cptra_pwrgood = true;
        v.next_cycle_high(1);

        v.input.cptra_rst_b = true;
        v.next_cycle_high(1);

        while !v.output.ready_for_fuses {
            v.next_cycle_high(1);
        }

        let mut m = ModelVerilated {
            v,
            generic_load_rx,
            output: Output::new(),
            trace_enabled: false,
        };

        m.soc_ifc().cptra_fuse_wr_done().write(|w| w.done(true));
        assert_eq!(m.soc_ifc().cptra_fuse_wr_done().read().done(), true);
        m.soc_ifc().cptra_bootfsm_go().write(|w| w.go(true));

        m.v.next_cycle_high(2);

        Ok(m)
    }

    fn apb_bus<'a>(&'a mut self) -> Self::TBus<'a> {
        VerilatedApbBus { v: &mut self.v }
    }

    fn step(&mut self) {
        self.v.next_cycle_high(1);
    }

    fn output(&mut self) -> &mut crate::Output {
        // Make sure output contains all the latest generic loads from the verilator model
        while let Ok(ch) = self.generic_load_rx.try_recv() {
            self.output.process_generic_load(ch)
        }

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
