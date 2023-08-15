/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

--*/

#![no_std]
extern crate core;

mod cfi;
mod cfi_counter;
mod xoshiro;

pub use cfi::*;
pub use cfi_counter::{CfiCounter, CfiInt};
pub use xoshiro::Xoshiro128;
