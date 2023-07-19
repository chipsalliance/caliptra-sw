// Licensed under the Apache-2.0 license

#![no_main]
#![feature(offset_of)]

use libfuzzer_sys::fuzz_target;

mod image_verify_fuzz_harness;
use caliptra_drivers::*;
use image_verify_fuzz_harness::harness;

fuzz_target!(|data: &[u8]| {
    harness(ResetReason::ColdReset, data);
});
