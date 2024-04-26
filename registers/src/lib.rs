// Licensed under the Apache-2.0 license
//
#![no_std]

#[cfg(not(feature = "hw-1.0"))]
pub use caliptra_registers_latest::*;

#[cfg(feature = "hw-1.0")]
pub use caliptra_registers_1_0::*;
