// Licensed under the Apache-2.0 license

//! Regenerates the CSRNG ADAPTP test data files in
//! `drivers/tests/drivers_integration_tests/test_data/csrng/`.
//!
//! Run with:
//!
//! ```text
//! cargo run -p caliptra-csrng-test-data-gen
//! ```
//!
//! The output is fully deterministic; running this command on a clean
//! tree should produce no diff. CI enforces this via the `regen` test
//! in this crate.

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .join("drivers_integration_tests/test_data/csrng");

    if !out_dir.is_dir() {
        eprintln!(
            "error: expected output directory does not exist: {}",
            out_dir.display()
        );
        std::process::exit(1);
    }

    for (i, spec) in caliptra_csrng_test_data_gen::SPECS.iter().enumerate() {
        let bytes = caliptra_csrng_test_data_gen::generate(i);
        let path = out_dir.join(spec.name);
        std::fs::write(&path, bytes).expect("write file");
        let total_ones: u32 = bytes.iter().map(|b| b.count_ones()).sum();
        println!(
            "wrote {} (total_ones={total_ones}, per_lane={:?})",
            path.display(),
            spec.per_lane
        );
    }
}
