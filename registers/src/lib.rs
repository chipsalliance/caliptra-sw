// Licensed under the Apache-2.0 license
//
#![no_std]

use mutually_exclusive_features::exactly_one_of;
exactly_one_of!("latest", "rev-2_0", "rev-2_1");

#[cfg(feature = "latest")]
pub use caliptra_registers_latest::*;

#[cfg(feature = "rev-2_1")]
compile_error!("TODO: add v2.1 HW register definitions");

#[cfg(feature = "rev-2_0")]
compile_error!("TODO: add v2.0 HW register definitions");
