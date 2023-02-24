use std::sync::mpsc;

use caliptra_emu_bus::Bus;
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use caliptra_verilated::CaliptraVerilated;

use crate::Output;

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
}

impl crate::Model for ModelVerilated {
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
}

#[cfg(test)]
mod tests {

    use crate::{mmio::Rv32GenMmio, model_verilated::ModelVerilated, InitParams, Model};
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_registers::soc_ifc;

    /// Generates RISC-V machine code that loads the characters 'h', 'i', then
    /// 0xff to the generic output wires
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

    const MBOX_ADDR_BASE: u32 = 0x3002_0000;
    const MBOX_ADDR_LOCK: u32 = MBOX_ADDR_BASE;
    const MBOX_ADDR_CMD: u32 = MBOX_ADDR_BASE + 0x0000_0008;

    #[test]
    fn test_apb() {
        let mut model = ModelVerilated::init(InitParams {
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
        let mut model = ModelVerilated::init(InitParams {
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
        let mut model = ModelVerilated::init(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.step_until_output("hi").unwrap();
    }

    #[test]
    fn test_output_failure() {
        let mut model = ModelVerilated::init(InitParams {
            rom: &gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            model.step_until_output("ha").err().unwrap().to_string(),
            "expected output \"ha\", was \"hi\""
        );
    }
}
