// Licensed under the Apache-2.0 license

#![feature(offset_of)]

use afl::fuzz;

mod image_verify_fuzz_harness;
use caliptra_drivers::*;
use image_verify_fuzz_harness::harness;

fn main() {
    fuzz!(|data: &[u8]| {
        harness(ResetReason::ColdReset, data);
    });
}
