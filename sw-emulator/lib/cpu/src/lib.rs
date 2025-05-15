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
mod internal_timers;
mod pic;
mod types;
pub mod xreg_file;

pub use cpu::StepAction;
pub use cpu::WatchPtrHit;
pub use cpu::WatchPtrKind;
pub use cpu::{CodeRange, CoverageBitmaps, Cpu, ImageInfo, InstrTracer, StackInfo, StackRange};
pub use csr_file::CsrFile;
pub use internal_timers::InternalTimers;
pub use pic::{IntSource, Irq, Pic, PicMmioRegisters};
pub use types::CpuArgs;
pub use types::CpuOrgArgs;
pub use types::RvInstr;
pub use types::RvInstr32;
