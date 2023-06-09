/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

--*/

#![no_std]
extern crate core;

mod cfi;
mod cfi_ctr;
mod xoshiro;

pub use cfi::*;
pub use cfi_ctr::{CfiCounter, CfiInt};
pub use xoshiro::{Xoshiro128, Xoshiro128Reg};
