// Licensed under the Apache-2.0 license

//! Verifies that the committed CSRNG ADAPTP test data files match what
//! the generator would produce. If this test fails, run:
//!
//! ```text
//! cargo run -p caliptra-csrng-test-data-gen
//! ```
//!
//! and commit the regenerated files.
//!
//! Skipped on FPGA test runners because they only ship test binaries,
//! not the source tree, and there is no value in re-running this test
//! on hardware anyway.

use std::path::PathBuf;

#[test]
#[cfg_attr(
    any(feature = "fpga_realtime", feature = "fpga_subsystem"),
    ignore = "test_data files are not shipped to the FPGA runner"
)]
fn committed_files_match_generator() {
    let test_data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .join("drivers_integration_tests/test_data/csrng");

    for (i, spec) in caliptra_csrng_test_data_gen::SPECS.iter().enumerate() {
        let expected = caliptra_csrng_test_data_gen::generate(i);
        let path = test_data_dir.join(spec.name);
        let actual = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("failed to read {}: {}", path.display(), e);
        });
        assert_eq!(
            actual.as_slice(),
            expected.as_slice(),
            "{} is out of sync with the generator; run `cargo run -p caliptra-csrng-test-data-gen` and commit the regenerated file",
            path.display()
        );
    }
}
