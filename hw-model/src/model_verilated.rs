// Licensed under the Apache-2.0 license

use std::sync::mpsc;

use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_verilated::CaliptraVerilated;

use crate::Output;
use std::env;

// TODO: Make this configurable
const SOC_PAUSER: u32 = 0xffff_ffff;

// How many clock cycles before emitting a TRNG nibble
const TRNG_DELAY: u32 = 4;

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

    csrng_nibbles: Box<dyn Iterator<Item = u8>>,
    trng_delay_remaining: u32,
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

        let mut m = ModelVerilated {
            v,
            generic_load_rx,
            output: Output::new(),
            trace_enabled: false,

            csrng_nibbles: params.csrng_nibbles,

            trng_delay_remaining: TRNG_DELAY,
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
        if self.v.output.etrng_req {
            if self.trng_delay_remaining == 0 {
                if let Some(val) = self.csrng_nibbles.next() {
                    self.v.input.itrng_valid = true;
                    self.v.input.itrng_data = val & 0xf;
                }
                self.trng_delay_remaining = TRNG_DELAY;
            } else {
                self.trng_delay_remaining -= 1;
            }
        }
        self.v.next_cycle_high(1);
        self.v.input.itrng_valid = false;
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
