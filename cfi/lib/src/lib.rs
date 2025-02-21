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

#[repr(C)]
pub struct CfiState {
    val: u32,
    mask: u32,
    prng: Xoshiro128,
}

#[cfg(feature = "cfi-test")]
static mut CFI_STATE: CfiState = CfiState {
    val: 0,
    mask: 0,
    prng: Xoshiro128::new_unseeded(),
};

#[cfg(not(feature = "cfi-test"))]
extern "C" {
    #[link_name = "CFI_STATE_ORG"]
    static mut CFI_STATE: CfiState;
}
