// Licensed under the Apache-2.0 license

use std::io::{stdout, LineWriter};

use caliptra_hw_model::{HwModel, InitParams};

fn run_driver_test(test_bin_name: &str) {
    let rom =
        caliptra_builder::build_firmware_rom("caliptra-drivers-test-bin", test_bin_name).unwrap();
    let mut model = caliptra_hw_model::create(InitParams {
        rom: &rom,
        ..Default::default()
    })
    .unwrap();

    // Wrap in a line-writer so output from different test threads doesn't multiplex within a line.
    model
        .copy_output_until_exit_success(LineWriter::new(stdout()))
        .unwrap();
}

#[test]
fn test_doe() {
    run_driver_test("doe");
}

#[test]
fn test_ecc384() {
    run_driver_test("ecc384");
}

#[test]
fn test_error_reporter() {
    run_driver_test("error_reporter");
}

#[test]
fn test_hmac384() {
    run_driver_test("hmac384");
}

#[test]
fn test_keyvault() {
    run_driver_test("keyvault");
}

#[test]
fn test_mailbox() {
    run_driver_test("mailbox");
}

#[test]
fn test_pcrbank() {
    run_driver_test("pcrbank");
}

#[test]
fn test_sha1() {
    run_driver_test("sha1");
}

#[test]
fn test_sha256() {
    run_driver_test("sha256");
}

#[test]
fn test_sha384() {
    run_driver_test("sha384");
}

#[test]
fn test_sha384acc() {
    run_driver_test("sha384acc");
}

#[test]
fn test_status_reporter() {
    run_driver_test("status_reporter");
}

#[test]
fn test_entropy_src() {
    run_driver_test("entropy_src");
}
