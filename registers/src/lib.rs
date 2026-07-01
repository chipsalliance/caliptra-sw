// Licensed under the Apache-2.0 license
//
#![no_std]

use mutually_exclusive_features::exactly_one_of;
exactly_one_of!("rev-latest", "rev-2_0", "rev-2_1");

#[cfg(feature = "rev-latest")]
pub use caliptra_registers_latest::*;

#[cfg(feature = "rev-2_1")]
pub use caliptra_registers_rev_2_1::*;

#[cfg(feature = "rev-2_0")]
compile_error!("TODO: add v2.0 HW register definitions");
