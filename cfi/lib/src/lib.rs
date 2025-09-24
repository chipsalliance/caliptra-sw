/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

--*/

#![cfg_attr(not(feature = "cfi-test"), no_std)]

extern crate core;

mod cfi;
mod cfi_counter;
mod xoshiro;

pub use cfi::*;
pub use cfi_counter::{CfiCounter, CfiInt};
pub use core::cell::Cell;
pub use xoshiro::Xoshiro128;

#[repr(C)]
pub struct CfiState {
    val: Cell<u32>,
    mask: Cell<u32>,
    prng: Xoshiro128,
}

#[cfg(feature = "cfi-test")]
thread_local! {
    static CFI_STATE: CfiState = CfiState {
        val: Cell::new(0),
        mask: Cell::new(0),
        prng: Xoshiro128::new_unseeded(),
    };
}

#[cfg(feature = "cfi-test")]
fn with_cfi_state<R, F: FnOnce(&CfiState) -> R>(f: F) -> R {
    CFI_STATE.with(f)
}

#[cfg(not(feature = "cfi-test"))]
extern "C" {
    #[link_name = "CFI_STATE_ORG"]
    static CFI_STATE: CfiState;
}

#[cfg(not(feature = "cfi-test"))]
fn with_cfi_state<R, F: FnOnce(&CfiState) -> R>(f: F) -> R {
    // This is only safe because we are in a single-threaded environment (CfiState is !Sync)
    f(unsafe { &CFI_STATE })
}
