// Licensed under the Apache-2.0 license

use super::BITS_PER_NIBBLE;
use caliptra_registers::entropy_src::regs::{
    AdaptpHiThresholdsReadVal, AdaptpLoThresholdsReadVal, RepcntThresholdsReadVal,
};

const HEALTH_TEST_WINDOW_BITS: usize = 2048;

pub struct HealthTester {
    itrng_nibbles: Box<dyn Iterator<Item = u8>>,
    pub repcnt: RepetitionCountTester,
    pub adaptp: AdaptiveProportionTester,
    boot_time_nibbles: Vec<u8>,
}

impl HealthTester {
    pub fn new(itrng_nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            itrng_nibbles,
            repcnt: RepetitionCountTester::new(),
            adaptp: AdaptiveProportionTester::new(),
            boot_time_nibbles: Vec::new(),
        }
    }

    pub fn test_boot_window(&mut self) {
        const NUM_NIBBLES: usize = HEALTH_TEST_WINDOW_BITS / BITS_PER_NIBBLE;

        self.boot_time_nibbles = self
            .itrng_nibbles
            .by_ref()
            .take(NUM_NIBBLES)
            .inspect(|nibble| {
                self.repcnt.feed(*nibble);
                self.adaptp.feed(*nibble);
            })
            .collect();

        assert_eq!(self.boot_time_nibbles.len(), NUM_NIBBLES, "itrng iterator should provide at least {NUM_NIBBLES} nibbles for boot-time health testing");

        // We'll want to pull these FIFO.
        self.boot_time_nibbles.reverse();
    }

    pub fn failures(&self) -> u32 {
        self.repcnt.failures() + self.adaptp.lo_failures() + self.adaptp.hi_failures()
    }
}

impl Iterator for HealthTester {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(nibble) = self.boot_time_nibbles.pop() {
            // First yield any boot-time nibbles we saved while health testing.
            Some(nibble)
        } else {
            // Then yield directly from the TRNG. Feed nibbles through health checks
            // for continuous testing.
            let nibble = self.itrng_nibbles.next()?;
            self.repcnt.feed(nibble);
            self.adaptp.feed(nibble);
            Some(nibble)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Bit {
    Zero,
    One,
}

pub struct RepetitionCountTester {
    threshold: u32,
    prev_nibble: [Option<Bit>; BITS_PER_NIBBLE],
    repetition_count: [u32; BITS_PER_NIBBLE],
    failures: u32,
}

impl RepetitionCountTester {
    pub fn new() -> Self {
        Self {
            threshold: 0xffff,
            prev_nibble: [None; BITS_PER_NIBBLE],
            repetition_count: [0; BITS_PER_NIBBLE],
            failures: 0,
        }
    }

    pub fn set_threshold(&mut self, threshold: RepcntThresholdsReadVal) {
        self.threshold = threshold.fips_thresh();
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn feed(&mut self, nibble: u8) {
        // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_repcnt_ht.sv.
        // If any of the four RNG wires repeats a bit, increment a wire-specific repetition counter.
        // If any of those repetition counters exceed the health check threshold, then increment
        // failures.

        for i in 0..BITS_PER_NIBBLE {
            let bit = match (nibble >> i) & 1 {
                0 => Bit::Zero,
                1 => Bit::One,
                _ => unreachable!("bit {i} of nibble={nibble} should only be 0 or 1"),
            };

            let is_repeat = self.prev_nibble[i].map_or(false, |prev_bit| prev_bit == bit);

            if is_repeat {
                self.repetition_count[i] += 1;

                if self.repetition_count[i] >= self.threshold {
                    self.failures += 1;
                }
            } else {
                self.repetition_count[i] = 0;
                self.prev_nibble[i] = Some(bit);
            }
        }
    }
}

pub struct AdaptiveProportionTester {
    lo_threshold: u32,
    hi_threshold: u32,
    lo_failures: u32,
    hi_failures: u32,
    num_ones_seen: u32,
    num_bits_seen: usize,
}

impl AdaptiveProportionTester {
    pub fn new() -> Self {
        Self {
            lo_threshold: 0,
            hi_threshold: 0xffff,
            lo_failures: 0,
            hi_failures: 0,
            num_ones_seen: 0,
            num_bits_seen: 0,
        }
    }

    pub fn set_lo_threshold(&mut self, threshold: AdaptpLoThresholdsReadVal) {
        self.lo_threshold = threshold.fips_thresh();
    }

    pub fn set_hi_threshold(&mut self, threshold: AdaptpHiThresholdsReadVal) {
        self.hi_threshold = threshold.fips_thresh();
    }

    pub fn lo_failures(&self) -> u32 {
        self.lo_failures
    }

    pub fn hi_failures(&self) -> u32 {
        self.hi_failures
    }

    pub fn feed(&mut self, nibble: u8) {
        // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_adaptp_ht.sv.
        assert!(
            nibble.count_ones() <= 4,
            "{nibble} should be a NIBBLE instead of a BYTE"
        );
        self.num_ones_seen += nibble.count_ones();
        self.num_bits_seen += BITS_PER_NIBBLE;

        if self.num_bits_seen >= HEALTH_TEST_WINDOW_BITS {
            if self.num_ones_seen < self.lo_threshold {
                self.lo_failures += 1;
            }

            if self.num_ones_seen > self.hi_threshold {
                self.hi_failures += 1;
            }

            // The test windows are not sliding. Reset for the next window.
            self.num_ones_seen = 0;
            self.num_bits_seen = 0;
        }
    }
}
