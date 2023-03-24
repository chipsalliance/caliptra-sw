// Licensed under the Apache-2.0 license

#![no_std]
#[cfg(not(feature = "std"))]
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("start.S"));
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("nmi.S"));
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("trap.S"));

pub mod trap;

pub use trap::{Exception, Interrupt, Trap, TrapRecord};
