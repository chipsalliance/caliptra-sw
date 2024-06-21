/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Library.

--*/

pub mod cpu;
mod csr_file;
mod instr;
mod pic;
mod types;
pub mod xreg_file;

pub use cpu::StepAction;
pub use cpu::WatchPtrHit;
pub use cpu::WatchPtrKind;
pub use cpu::{CoverageBitmaps, Cpu, InstrTracer};
pub use csr_file::CsrFile;
pub use pic::{IntSource, Irq, Pic, PicMmioRegisters};
pub use types::RvInstr;
