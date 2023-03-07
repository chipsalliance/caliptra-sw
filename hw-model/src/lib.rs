use std::error::Error;

use caliptra_emu_bus::Bus;

pub mod mmio;
mod model_emulated;

#[cfg(feature = "verilator")]
mod model_verilated;
mod output;
mod rv32_builder;

use mmio::BusMmio;
pub use output::Output;

pub use model_emulated::ModelEmulated;

#[cfg(feature = "verilator")]
pub use model_verilated::ModelVerilated;

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
// from tests.
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
