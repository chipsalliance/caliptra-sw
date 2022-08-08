/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Library.

--*/

mod cpu;
mod csr_file;
mod instr;
mod macros;
mod types;
mod xreg_file;

pub use cpu::Cpu;
pub use cpu::StepAction;
