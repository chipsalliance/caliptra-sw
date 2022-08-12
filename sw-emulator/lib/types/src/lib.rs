/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Types library.

--*/

mod exception;
mod macros;

pub use crate::exception::{RvException, RvExceptionCause};

/// RISCV Data width
pub type RvData = u32;

/// RISCV Address width
pub type RvAddr = u32;

/// RISCV Interrupt Request
pub type RvIrq = u16;

emu_enum!(
    /// RISCV IO Operation size
    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub RvSize;
    usize;
    {
        Byte = 1,
        HalfWord = 2,
        Word = 4,
    };
    Invalid
);
