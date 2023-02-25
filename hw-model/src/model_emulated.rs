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
            rom: rom,
            tb_services_cb: TbServicesCb::new(tb_services_cb),
            ..CaliptraRootBusArgs::default()
        };
        let cpu = Cpu::new(CaliptraRootBus::new(&clock, bus_args), clock);

        Self { cpu: cpu }
    }
}

pub struct ModelEmulated {
    emu: CaliptraEmulator,
    output: Output,
    generic_load_rx: mpsc::Receiver<u8>,
}

impl crate::Model for ModelEmulated {
    type TBus<'a> = EmulatedApbBus<'a>;

    fn init(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized,
    {
        let (generic_load_tx, generic_load_rx) = mpsc::channel();
        let m = ModelEmulated {
            generic_load_rx: generic_load_rx,
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
    fn apb_bus<'a>(&'a mut self) -> Self::TBus<'a> {
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
}

#[cfg(test)]
mod tests {
    use crate::{mmio::Rv32GenMmio, model_emulated::ModelEmulated, InitParams, Model};
    use caliptra_emu_types::RvSize;
    use caliptra_registers::soc_ifc;

    use caliptra_emu_bus::Bus;
    const MBOX_ADDR_BASE: u32 = 0x3002_0000;
    const MBOX_ADDR_LOCK: u32 = MBOX_ADDR_BASE;
    const MBOX_ADDR_CMD: u32 = MBOX_ADDR_BASE + 0x0000_0008;

    fn gen_image_hi() -> Vec<u8> {
        let rv32_gen = Rv32GenMmio::new();
        let soc_ifc =
            unsafe { soc_ifc::RegisterBlock::new_with_mmio(0x3003_0000 as *mut u32, &rv32_gen) };
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| b'h'.into());
        soc_ifc
            .cptra_generic_output_wires()
            .at(0)
            .write(|_| b'i'.into());
        soc_ifc.cptra_generic_output_wires().at(0).write(|_| 0xff);
        rv32_gen.build()
    }

    #[test]
    fn test_apb() {
        let mut model = ModelEmulated::init(InitParams {
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            0
        );

        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_LOCK).unwrap(),
            1
        );

        model
            .apb_bus()
            .write(RvSize::Word, MBOX_ADDR_CMD, 4242)
            .unwrap();
        assert_eq!(
            model.apb_bus().read(RvSize::Word, MBOX_ADDR_CMD).unwrap(),
            4242
        );
    }

    #[test]
    fn test_mbox() {
        // Same as test_apb, but uses higher-level register interface
        let mut model = ModelEmulated::init(InitParams {
            ..Default::default()
        })
        .unwrap();

        assert_eq!(model.soc_mbox().lock().read().lock(), false);

        assert_eq!(model.soc_mbox().lock().read().lock(), true);

        model.soc_mbox().cmd().write(|_| 4242);
        assert_eq!(model.soc_mbox().cmd().read(), 4242);
    }

    #[test]
    fn test_execution() {
        let mut model = ModelEmulated::init(InitParams {
            rom: &&gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.step_until_output("hi").unwrap();
    }

    #[test]
    fn test_output_failure() {
        let mut model = ModelEmulated::init(InitParams {
            rom: &&gen_image_hi(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            model.step_until_output("ha").err().unwrap().to_string(),
            "expected output \"ha\", was \"hi\""
        );
    }
}
