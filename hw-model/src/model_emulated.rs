// Licensed under the Apache-2.0 license

use std::error::Error;
use std::sync::mpsc;

use caliptra_emu_bus::Clock;
use caliptra_emu_cpu::Cpu;
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs, TbServicesCb};
use caliptra_emu_types::{RvAddr, RvData, RvSize};

use crate::InitParams;
use crate::Output;
use caliptra_emu_bus::Bus;

pub struct EmulatedApbBus<'a> {
    emu: &'a mut CaliptraEmulator,
}

impl<'a> Bus for EmulatedApbBus<'a> {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, caliptra_emu_bus::BusError> {
        self.emu.cpu.bus.read(size, addr)
    }
    fn write(
        &mut self,
        size: RvSize,
        addr: RvAddr,
        val: RvData,
    ) -> Result<(), caliptra_emu_bus::BusError> {
        self.emu.cpu.bus.write(size, addr, val)
    }
}

struct CaliptraEmulator {
    cpu: Cpu<CaliptraRootBus>,
}

impl CaliptraEmulator {
    pub fn new(rom: Vec<u8>, tb_services_cb: Box<dyn FnMut(u8)>) -> Self {
        let clock = Clock::new();
        let bus_args = CaliptraRootBusArgs {
            rom,
            tb_services_cb: TbServicesCb::new(tb_services_cb),
            ..CaliptraRootBusArgs::default()
        };
        let cpu = Cpu::new(CaliptraRootBus::new(&clock, bus_args), clock);

        Self { cpu }
    }
}

pub struct ModelEmulated {
    emu: CaliptraEmulator,
    output: Output,
    generic_load_rx: mpsc::Receiver<u8>,
}

impl crate::HwModel for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn init(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let (generic_load_tx, generic_load_rx) = mpsc::channel();
        let m = ModelEmulated {
            generic_load_rx,
            output: Output::new(),
            emu: CaliptraEmulator::new(
                params.rom.to_vec(),
                Box::new(move |ch| {
                    let _ = generic_load_tx.send(ch);
                }),
            ),
        };

        Ok(m)
    }
    fn apb_bus(&mut self) -> Self::TBus<'_> {
        EmulatedApbBus { emu: &mut self.emu }
    }

    fn step(&mut self) {
        self.emu.cpu.step(None);
    }

    fn output(&mut self) -> &mut Output {
        // Make sure output contains all the latest generic loads from the verilator model
        while let Ok(ch) = self.generic_load_rx.try_recv() {
            self.output.process_generic_load(ch)
        }

        &mut self.output
    }

    fn tracing_hint(&mut self, _enable: bool) {
        todo!();
    }
}
