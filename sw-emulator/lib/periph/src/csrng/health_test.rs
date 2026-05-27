// Licensed under the Apache-2.0 license

use super::BITS_PER_NIBBLE;
use caliptra_registers::entropy_src::regs::{
    AdaptpHiThresholdsReadVal, AdaptpLoThresholdsReadVal, RepcntThresholdsReadVal,
    RepcntsThresholdsReadVal,
};

/// Default health-test window size in bits. Matches the RTL register
/// reset value (`HEALTH_TEST_WINDOWS.FIPS_WINDOW = 0x200` clock cycles
/// times 4 bits per cycle = 2048 bits aggregate, 512 bits per lane).
/// The ROM overrides this at boot via the `HEALTH_TEST_WINDOWS` register.
const DEFAULT_WINDOW_SIZE_BITS: usize = 2048;

pub struct HealthTester {
    itrng_nibbles: Box<dyn Iterator<Item = u8>>,
    pub repcnt: RepetitionCountTester,
    pub repcnts: RepetitionCountSymbolTester,
    pub adaptp: AdaptiveProportionTester,
    boot_time_nibbles: Vec<u8>,
    window_size_bits: usize,
}

impl HealthTester {
    pub fn new(itrng_nibbles: Box<dyn Iterator<Item = u8>>) -> Self {
        Self {
            itrng_nibbles,
            repcnt: RepetitionCountTester::new(),
            repcnts: RepetitionCountSymbolTester::new(),
            adaptp: AdaptiveProportionTester::new(),
            boot_time_nibbles: Vec::new(),
            window_size_bits: DEFAULT_WINDOW_SIZE_BITS,
        }
    }

    /// Returns the current FIPS health-test window size in bits.
    pub fn window_size_bits(&self) -> usize {
        self.window_size_bits
    }

    /// Updates the FIPS health-test window size in bits. Called when the
    /// HEALTH_TEST_WINDOWS register is written. The adaptive-proportion
    /// tester's per-window state is kept in sync.
    pub fn set_window_size_bits(&mut self, bits: usize) {
        self.window_size_bits = bits;
        self.adaptp.set_window_size_bits(bits);
    }

    pub fn test_boot_window(&mut self) {
        // The RTL tests TWO consecutive windows during boot-time health testing.
        // See entropy_src_main_sm.sv: StartupHTStart -> StartupPhase1 -> StartupPass1 -> Sha3Process
        // Only after both windows pass does boot complete.
        const NUM_BOOT_WINDOWS: usize = 2;
        let num_nibbles = NUM_BOOT_WINDOWS * self.window_size_bits / BITS_PER_NIBBLE;

        self.boot_time_nibbles = self
            .itrng_nibbles
            .by_ref()
            .take(num_nibbles)
            .inspect(|nibble| {
                self.repcnt.feed(*nibble);
                self.repcnts.feed(*nibble);
                self.adaptp.feed(*nibble);
            })
            .collect();

        assert_eq!(
            self.boot_time_nibbles.len(),
            num_nibbles,
            "itrng iterator should provide at least {num_nibbles} nibbles for boot-time health testing"
        );

        // We'll want to pull these FIFO.
        self.boot_time_nibbles.reverse();
    }

    pub fn failures(&self) -> u32 {
        self.repcnt.failures()
            + self.repcnts.failures()
            + self.adaptp.lo_failures()
            + self.adaptp.hi_failures()
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
            self.repcnts.feed(nibble);
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
            repetition_count: [1; BITS_PER_NIBBLE], // the hardware starts the counter at 1
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

            let is_repeat = self.prev_nibble[i] == Some(bit);

            if is_repeat {
                self.repetition_count[i] += 1;

                if self.repetition_count[i] >= self.threshold {
                    self.failures += 1;
                }
            } else {
                self.repetition_count[i] = 1;
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
    // When true, the test scores the sum of ones across all RNG lanes
    // against hi/lo thresholds (mubi4 strict-true value). When false,
    // the test scores each lane individually: a failure is counted if
    // any lane's count exceeds hi or falls below lo.
    threshold_scope: bool,
    per_lane_ones: [u32; BITS_PER_NIBBLE],
    num_bits_seen: usize,
    window_size_bits: usize,
}

impl AdaptiveProportionTester {
    pub fn new() -> Self {
        Self {
            lo_threshold: 0,
            hi_threshold: 0xffff,
            lo_failures: 0,
            hi_failures: 0,
            threshold_scope: false,
            per_lane_ones: [0; BITS_PER_NIBBLE],
            num_bits_seen: 0,
            window_size_bits: DEFAULT_WINDOW_SIZE_BITS,
        }
    }

    pub fn set_lo_threshold(&mut self, threshold: AdaptpLoThresholdsReadVal) {
        self.lo_threshold = threshold.fips_thresh();
    }

    pub fn set_hi_threshold(&mut self, threshold: AdaptpHiThresholdsReadVal) {
        self.hi_threshold = threshold.fips_thresh();
    }

    pub fn set_threshold_scope(&mut self, threshold_scope: bool) {
        self.threshold_scope = threshold_scope;
    }

    /// Set the per-window size in bits. Mid-window changes restart the
    /// current window from scratch.
    pub fn set_window_size_bits(&mut self, bits: usize) {
        self.window_size_bits = bits;
        self.per_lane_ones = [0; BITS_PER_NIBBLE];
        self.num_bits_seen = 0;
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
        for (i, lane) in self.per_lane_ones.iter_mut().enumerate() {
            *lane += u32::from((nibble >> i) & 1);
        }
        self.num_bits_seen += BITS_PER_NIBBLE;

        if self.num_bits_seen >= self.window_size_bits {
            // adaptp_ht.sv:
            //   test_cnt_hi_o = threshold_scope_i ? sum(lanes) : max(lanes)
            //   test_cnt_lo_o = threshold_scope_i ? sum(lanes) : min(lanes)
            //   fail_hi = (test_cnt_hi_o > thresh_hi)
            //   fail_lo = (test_cnt_lo_o < thresh_lo)
            let sum: u32 = self.per_lane_ones.iter().sum();
            let test_cnt_hi = if self.threshold_scope {
                sum
            } else {
                *self.per_lane_ones.iter().max().expect("4 lanes")
            };
            let test_cnt_lo = if self.threshold_scope {
                sum
            } else {
                *self.per_lane_ones.iter().min().expect("4 lanes")
            };

            if test_cnt_lo < self.lo_threshold {
                self.lo_failures += 1;
            }

            if test_cnt_hi > self.hi_threshold {
                self.hi_failures += 1;
            }

            // The test windows are not sliding. Reset for the next window.
            self.per_lane_ones = [0; BITS_PER_NIBBLE];
            self.num_bits_seen = 0;
        }
    }
}

/// Repetition Count Symbol Tester (repcnts)
///
/// Unlike the per-wire repcnt test, this tests if the entire 4-bit symbol (nibble)
/// repeats consecutively. If the same nibble value appears N times in a row where
/// N >= threshold, a failure is counted.
///
/// See NIST.SP.800-90B section 4.4.1 and entropy_src_repcnts_ht.sv in OpenTitan.
pub struct RepetitionCountSymbolTester {
    threshold: u32,
    prev_nibble: Option<u8>,
    repetition_count: u32,
    failures: u32,
}

impl RepetitionCountSymbolTester {
    pub fn new() -> Self {
        Self {
            threshold: 0xffff,
            prev_nibble: None,
            repetition_count: 1, // the hardware starts the counter at 1
            failures: 0,
        }
    }

    pub fn set_threshold(&mut self, threshold: RepcntsThresholdsReadVal) {
        self.threshold = threshold.fips_thresh();
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn feed(&mut self, nibble: u8) {
        // Replicate the logic in caliptra-rtl/src/entropy_src/rtl/entropy_src_repcnts_ht.sv.
        // If the entire 4-bit symbol repeats, increment the repetition counter.
        // If the counter reaches the threshold, increment failures.

        let is_repeat = self.prev_nibble == Some(nibble);

        if is_repeat {
            self.repetition_count += 1;

            if self.repetition_count >= self.threshold {
                self.failures += 1;
            }
        } else {
            self.repetition_count = 1;
            self.prev_nibble = Some(nibble);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the Adaptive Proportion health-check model.
    use super::*;

    const NIBBLES_PER_WINDOW: usize = DEFAULT_WINDOW_SIZE_BITS / BITS_PER_NIBBLE;

    fn make_adaptp(hi: u32, lo: u32, threshold_scope: bool) -> AdaptiveProportionTester {
        let mut t = AdaptiveProportionTester::new();
        // The FIPS_THRESH field occupies the low 16 bits of the register.
        t.set_hi_threshold(AdaptpHiThresholdsReadVal::from(hi & 0xffff));
        t.set_lo_threshold(AdaptpLoThresholdsReadVal::from(lo & 0xffff));
        t.set_threshold_scope(threshold_scope);
        t
    }

    /// Feed an exact per-lane ones distribution over one window.
    /// Distributes ones to the front of the window for each lane.
    fn feed_per_lane(tester: &mut AdaptiveProportionTester, per_lane: [u32; 4]) {
        for i in 0..NIBBLES_PER_WINDOW {
            let mut nibble = 0u8;
            for (lane, &ones) in per_lane.iter().enumerate() {
                if (i as u32) < ones {
                    nibble |= 1 << lane;
                }
            }
            tester.feed(nibble);
        }
    }

    /// Sanity: counters reset on window wrap so multiple windows are
    /// scored independently.
    #[test]
    fn window_counters_reset_between_windows() {
        let mut t = make_adaptp(384, 128, false);
        // Window 1: balanced - should pass both bounds.
        feed_per_lane(&mut t, [256, 256, 256, 256]);
        assert_eq!(t.hi_failures(), 0);
        assert_eq!(t.lo_failures(), 0);
        // Window 2: lane 0 stuck-at-zero - should fail LO only.
        feed_per_lane(&mut t, [0, 256, 256, 256]);
        assert_eq!(t.hi_failures(), 0);
        assert_eq!(t.lo_failures(), 1);
    }

    /// Per-lane scoring (THRESHOLD_SCOPE = FALSE): the RTL uses
    /// `min(lanes) < thresh_lo` and `max(lanes) > thresh_hi`. Any single
    /// lane in violation triggers the corresponding failure.
    #[test]
    fn per_lane_scope_uses_min_and_max() {
        // hi=384, lo=128 are the ROM defaults for a 512-bit per-lane window.
        let mut t = make_adaptp(384, 128, false);

        // [128, 256, 256, 256] - lane 0 at LO boundary, exactly equal -> pass.
        // RTL uses strict `<`, so equal must not fail.
        feed_per_lane(&mut t, [128, 256, 256, 256]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 0), "boundary LO");

        // [127, 256, 256, 256] - lane 0 below LO -> fail LO via min.
        feed_per_lane(&mut t, [127, 256, 256, 256]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 1), "below LO");

        // [256, 256, 256, 384] - lane 3 at HI boundary, exactly equal -> pass.
        // RTL uses strict `>`, so equal must not fail.
        feed_per_lane(&mut t, [256, 256, 256, 384]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 1), "boundary HI");

        // [256, 256, 256, 385] - lane 3 above HI -> fail HI via max.
        feed_per_lane(&mut t, [256, 256, 256, 385]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (1, 1), "above HI");
    }

    /// Aggregate scoring (THRESHOLD_SCOPE = TRUE): the RTL uses
    /// `sum(lanes) < thresh_lo` and `sum(lanes) > thresh_hi`.
    #[test]
    fn aggregate_scope_uses_sum() {
        // hi=1536, lo=512 mimics the legacy aggregate ROM defaults.
        let mut t = make_adaptp(1536, 512, true);

        // Sum = 4*128 = 512, exactly at LO -> pass (strict `<`).
        feed_per_lane(&mut t, [128, 128, 128, 128]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 0), "sum=LO");

        // Lane 0 has 117 ones but other lanes compensate: sum = 117+128+130+137 = 512.
        // Per-lane scoring would have failed (117 < 128), aggregate must pass.
        feed_per_lane(&mut t, [117, 128, 130, 137]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 0), "uneven sum=LO");

        // Sum = 511 -> fail LO.
        feed_per_lane(&mut t, [117, 128, 129, 137]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 1), "sum below LO");

        // Sum = 4*384 = 1536, exactly at HI -> pass.
        feed_per_lane(&mut t, [384, 384, 384, 384]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (0, 1), "sum=HI");

        // Sum = 1537 -> fail HI.
        feed_per_lane(&mut t, [385, 384, 384, 384]);
        assert_eq!((t.hi_failures(), t.lo_failures()), (1, 1), "sum above HI");
    }

    /// All-zeros and all-ones are the canonical catastrophic failure
    /// patterns the NIST AP test is designed to detect.
    #[test]
    fn catastrophic_patterns_trigger_failure() {
        // Per-lane scope: a single stuck-at-zero lane fails LO.
        let mut t = make_adaptp(384, 128, false);
        for _ in 0..NIBBLES_PER_WINDOW {
            // lane 0 stuck-low, others stuck-high
            t.feed(0b1110);
        }
        // min = 0 < 128, max = 512 > 384.
        assert!(t.lo_failures() >= 1);
        assert!(t.hi_failures() >= 1);
    }

    /// The boot-time path runs two consecutive windows; failures
    /// accumulate.
    #[test]
    fn failures_accumulate_across_windows() {
        let mut t = make_adaptp(384, 128, false);
        // Two windows that both fail LO on lane 0.
        feed_per_lane(&mut t, [0, 256, 256, 256]);
        feed_per_lane(&mut t, [0, 256, 256, 256]);
        assert_eq!(t.lo_failures(), 2);
    }

    /// Partial windows do not score.
    #[test]
    fn partial_window_does_not_score() {
        let mut t = make_adaptp(384, 128, false);
        // Feed less than a full window.
        for _ in 0..(NIBBLES_PER_WINDOW - 1) {
            t.feed(0); // every lane stuck-low, but window is incomplete
        }
        assert_eq!(t.hi_failures(), 0);
        assert_eq!(t.lo_failures(), 0);
    }
}
