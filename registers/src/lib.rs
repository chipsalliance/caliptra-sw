// Licensed under the Apache-2.0 license
//
#![no_std]

#[cfg(feature = "hw-latest")]
pub use caliptra_registers_latest::*;

#[cfg(not(feature = "hw-latest"))]
pub use caliptra_registers_1_0::*;
