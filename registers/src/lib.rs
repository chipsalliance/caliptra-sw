// Licensed under the Apache-2.0 license
//
#![no_std]
#![doc = "Register accessors for the pinned Caliptra 2.2 development hardware."]
pub use caliptra_registers_latest::*;

pub use crate::soc_ifc::regs::{
    EntropyConfig0WriteVal as CptraItrngEntropyConfig0WriteVal,
    EntropyConfig1WriteVal as CptraItrngEntropyConfig1WriteVal,
};
