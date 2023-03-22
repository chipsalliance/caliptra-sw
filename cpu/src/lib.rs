// Licensed under the Apache-2.0 license

#![no_std]
pub mod trap;

pub use trap::{Exception, Interrupt, Trap, TrapRecord};
