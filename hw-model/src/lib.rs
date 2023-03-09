// Licensed under the Apache-2.0 license

use std::error::Error;

use caliptra_emu_bus::Bus;

pub mod mmio;
mod model_emulated;

#[cfg(feature = "verilator")]
mod model_verilated;
mod output;
mod rv32_builder;

mod soc_flows;

use mmio::BusMmio;
pub use output::Output;

pub use model_emulated::ModelEmulated;
pub use soc_flows::SocFlows;

#[cfg(feature = "verilator")]
pub use model_verilated::ModelVerilated;

/// Constructs an HwModel based on the cargo features and environment
/// variables. Most test cases that need to construct a HwModel should use this
/// function.
///
/// Ideally this function would return `Result<impl HwModel, Box<dyn Error>>`
/// to prevent users from calling functions that weren't available on HwModel
/// implementations.  Unfortunately, rust-analyzer (used by IDEs) can't fully
/// resolve associated types from `impl Trait`, so this function will return the
/// full type until they fix that. Users should treat this return type as if it
/// were `impl HwModel`.
#[cfg(not(feature = "verilator"))]
pub fn create(params: InitParams) -> Result<ModelEmulated, Box<dyn Error>> {
    ModelEmulated::init(params)
}

#[cfg(feature = "verilator")]
pub fn create(params: InitParams) -> Result<ModelVerilated, Box<dyn Error>> {
    ModelVerilated::init(params)
}

#[derive(Default)]
pub struct InitParams<'a> {
    // The contents of the boot ROM
    pub rom: &'a [u8],

    // The initial contents of the DCCM SRAM
    pub dccm: &'a [u8],

    // The initial contents of the ICCM SRAM
    pub iccm: &'a [u8],
}

pub enum ModelError {}

// Represents a emulator or simulation of the caliptra hardware, to be called
// from tests. Typically, test cases should use `create()` to create a model
// based on the cargo features (and any model-specific environment variables).
pub trait HwModel {
    type TBus<'a>: Bus
    where
        Self: 'a;

    fn init(params: InitParams) -> Result<Self, Box<dyn Error>>
    where
        Self: Sized;

    /// The APB bus from the SoC to Caliptra
    ///
    /// WARNING: Reading or writing to this bus may involve the Caliptra
    /// microcontroller executing a few instructions
    fn apb_bus<'a>(&'a mut self) -> Self::TBus<'a>;

    /// Step execution ahead one clock cycle.
    fn step(&mut self);

    /// Any UART-ish output written by the microcontroller will be available here.
    fn output(&mut self) -> &mut Output;

    /// Execute until the result of `predicate` becomes true.
    fn step_until(&mut self, mut predicate: impl FnMut(&mut Self) -> bool) {
        while !predicate(self) {
            self.step();
        }
    }

    /// Execute until the output contains `expected_output`.
    fn step_until_output(&mut self, expected_output: &str) -> Result<(), Box<dyn Error>> {
        self.step_until(|m| m.output().peek().len() >= expected_output.len());
        if &self.output().peek()[..expected_output.len()] != expected_output {
            return Err(format!(
                "expected output {:?}, was {:?}",
                expected_output,
                self.output().peek()
            )
            .into());
        }
        Ok(())
    }

    /// A register block that can be used to manipulate the soc_ifc peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_ifc<'a>(
        &'a mut self,
    ) -> caliptra_registers::soc_ifc::RegisterBlock<BusMmio<Self::TBus<'a>>> {
        unsafe {
            caliptra_registers::soc_ifc::RegisterBlock::new_with_mmio(
                0x3003_0000 as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }

    /// A register block that can be used to manipulate the mbox peripheral
    /// over the simulated SoC->Caliptra APB bus.
    fn soc_mbox<'a>(
        &'a mut self,
    ) -> caliptra_registers::mbox::RegisterBlock<BusMmio<Self::TBus<'a>>> {
        unsafe {
            caliptra_registers::mbox::RegisterBlock::new_with_mmio(
                0x3002_0000 as *mut u32,
                BusMmio::new(self.apb_bus()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{mmio::Rv32GenMmio, HwModel, InitParams};
    use caliptra_emu_bus::Bus;
    use caliptra_emu_types::RvSize;
    use caliptra_registers::soc_ifc;

    use crate as caliptra_hw_model;

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
        let mut model = caliptra_hw_model::create(InitParams {
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
        let mut model = caliptra_hw_model::create(InitParams {
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
        let mut model = caliptra_hw_model::create(InitParams {
            rom: &&gen_image_hi(),
            ..Default::default()
        })
        .unwrap();

        model.step_until_output("hi").unwrap();
    }

    #[test]
    fn test_output_failure() {
        let mut model = caliptra_hw_model::create(InitParams {
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
