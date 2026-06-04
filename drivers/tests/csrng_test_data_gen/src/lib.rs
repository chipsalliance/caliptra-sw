// Licensed under the Apache-2.0 license

//! Deterministic generator for the CSRNG ADAPTP integration-test windows.
//!
//! With `CONF.THRESHOLD_SCOPE = FALSE` the entropy_src ADAPTP health test
//! scores each of the 4 RNG bus lanes independently. The integration tests
//! at `drivers/tests/drivers_integration_tests/main.rs` use 8 hand-crafted
//! 1024-nibble windows where each lane carries a specific number of ones.
//! This crate generates those windows from a fixed seed so the binary
//! files in `drivers_integration_tests/test_data/csrng` are reproducible.
//!
//! Each generated window is also validated against the default RepCnt and
//! RepCntS thresholds (41) so incidental long runs cannot mask the ADAPTP
//! behavior we want to exercise.

use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;

/// Number of nibbles in a single startup health-test window. With 4 lanes
/// each lane is scored over `WINDOW_NIBBLES` bits per window.
pub const WINDOW_NIBBLES: usize = 1024;

/// Default RepCnt/RepCntS threshold (the ROM-applied default).
/// A run of identical bits/nibbles of length >= REPCNT_LIMIT would
/// cause the repetition-count tests to fail and mask the ADAPTP intent.
pub const REPCNT_LIMIT: u32 = 41;

/// Number of RNG bus lanes.
pub const NUM_LANES: usize = 4;

/// One file's worth of test data: the file name and the desired per-lane
/// ones counts.
#[derive(Clone, Copy)]
pub struct Spec {
    pub name: &'static str,
    pub per_lane: [u32; NUM_LANES],
}

/// The full set of files the generator writes. Aggregate totals are
/// reflected in the file name (per_lane[0] + per_lane[1] + ... = name).
///
/// The thresholds these files exercise (in a 1024-bit per-lane window):
///   * ROM defaults: HI = 768, LO = 256.
///   * SoC-supplied override (test_csrng_adaptive_proportion): HI = 612, LO = 412.
pub const SPECS: &[Spec] = &[
    // Boundary-pass at the default LO threshold (256 per lane).
    Spec {
        name: "1024_ones_3072_zeros",
        per_lane: [256, 256, 256, 256],
    },
    // Boundary-pass at the default HI threshold (768 per lane).
    Spec {
        name: "3072_ones_1024_zeros",
        per_lane: [768, 768, 768, 768],
    },
    // One lane below the default LO threshold.
    Spec {
        name: "1023_ones_3073_zeros",
        per_lane: [255, 256, 256, 256],
    },
    // One lane above the default HI threshold.
    Spec {
        name: "3073_ones_1023_zeros",
        per_lane: [769, 768, 768, 768],
    },
    // Boundary-pass at the SoC-supplied LO threshold (412 per lane).
    Spec {
        name: "1648_ones_2448_zeros",
        per_lane: [412, 412, 412, 412],
    },
    // Boundary-pass at the SoC-supplied HI threshold (612 per lane).
    Spec {
        name: "2448_ones_1648_zeros",
        per_lane: [612, 612, 612, 612],
    },
    // One lane below the SoC-supplied LO threshold.
    Spec {
        name: "1647_ones_2449_zeros",
        per_lane: [411, 412, 412, 412],
    },
    // One lane above the SoC-supplied HI threshold.
    Spec {
        name: "2449_ones_1647_zeros",
        per_lane: [613, 612, 612, 612],
    },
];

/// Master seed for the deterministic RNG. Changing this value changes
/// every output file, so it should only be touched intentionally.
pub const MASTER_SEED: u64 = 0x_CA1B_3771_ADA9_7B0A;

/// Compute the longest run of identical values returned by `f` over `bytes`.
fn longest_run<F: Fn(u8) -> u8>(bytes: &[u8], f: F) -> u32 {
    let mut run = 1u32;
    let mut max_run = 1u32;
    let mut prev = f(bytes[0]);
    for &b in &bytes[1..] {
        let cur = f(b);
        if cur == prev {
            run += 1;
            if run > max_run {
                max_run = run;
            }
        } else {
            run = 1;
            prev = cur;
        }
    }
    max_run
}

/// Build a candidate window by independently shuffling each lane's
/// target ones distribution and packing the four lanes into nibbles.
fn build_window(rng: &mut StdRng, per_lane: &[u32; NUM_LANES]) -> [u8; WINDOW_NIBBLES] {
    let mut columns: [[u8; WINDOW_NIBBLES]; NUM_LANES] = [[0; WINDOW_NIBBLES]; NUM_LANES];
    for (lane, ones) in per_lane.iter().enumerate() {
        let ones = *ones as usize;
        assert!(ones <= WINDOW_NIBBLES);
        for slot in columns[lane].iter_mut().take(ones) {
            *slot = 1;
        }
        columns[lane].shuffle(rng);
    }
    let mut out = [0u8; WINDOW_NIBBLES];
    for (j, byte) in out.iter_mut().enumerate() {
        let mut nibble = 0u8;
        for (lane, col) in columns.iter().enumerate() {
            nibble |= col[j] << lane;
        }
        *byte = nibble;
    }
    out
}

/// Check that `bytes` exactly satisfies the per-lane ones counts and
/// that no lane (and no nibble) has a run >= [`REPCNT_LIMIT`].
fn is_valid(bytes: &[u8; WINDOW_NIBBLES], per_lane: &[u32; NUM_LANES]) -> bool {
    for (lane, expected) in per_lane.iter().enumerate() {
        let count: u32 = bytes.iter().map(|b| u32::from((b >> lane) & 1)).sum();
        if count != *expected {
            return false;
        }
        if longest_run(bytes, |b| (b >> lane) & 1) >= REPCNT_LIMIT {
            return false;
        }
    }
    if longest_run(bytes, |b| b) >= REPCNT_LIMIT {
        return false;
    }
    true
}

/// Deterministically generate the window for one spec. Each spec gets
/// its own RNG branch derived from [`MASTER_SEED`] and the spec's
/// position in [`SPECS`]; if a candidate window fails validation we
/// re-roll from the next seed offset until one passes.
pub fn generate(spec_index: usize) -> [u8; WINDOW_NIBBLES] {
    let spec = &SPECS[spec_index];
    let base = MASTER_SEED.wrapping_add((spec_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    for attempt in 0u64.. {
        let seed = base.wrapping_add(attempt);
        let mut rng = StdRng::seed_from_u64(seed);
        let bytes = build_window(&mut rng, &spec.per_lane);
        if is_valid(&bytes, &spec.per_lane) {
            return bytes;
        }
    }
    unreachable!("generation must converge; per_lane={:?}", spec.per_lane);
}

/// Generate every file's bytes into a `(name, bytes)` list. Useful for
/// the regen test which compares against the on-disk files.
pub fn generate_all() -> Vec<(&'static str, [u8; WINDOW_NIBBLES])> {
    (0..SPECS.len())
        .map(|i| (SPECS[i].name, generate(i)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spec_matches_aggregate_in_filename() {
        for spec in SPECS {
            let total: u32 = spec.per_lane.iter().sum();
            let parsed_ones: u32 = spec
                .name
                .split('_')
                .next()
                .unwrap()
                .parse()
                .expect("filename starts with the aggregate ones count");
            assert_eq!(total, parsed_ones, "spec={}", spec.name);
        }
    }

    #[test]
    fn generation_is_deterministic_and_valid() {
        for (i, spec) in SPECS.iter().enumerate() {
            let a = generate(i);
            let b = generate(i);
            assert_eq!(a, b, "{} should be deterministic", spec.name);
            assert!(
                is_valid(&a, &spec.per_lane),
                "{} should satisfy per-lane ones counts and repcnt limits",
                spec.name
            );
        }
    }
}
