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
    let rom =
        caliptra_builder::build_firmware_rom("caliptra-drivers-test-bin", "entropy_src").unwrap();
    let mut model = caliptra_hw_model::create(InitParams {
        rom: &rom,
        csrng_nibbles: Box::new([
            0xd, 0x2, 0xe, 0x3, 0x1, 0x4, 0x7, 0x9,
            0xf, 0xe, 0x1, 0xb, 0x7, 0xd, 0x0, 0x1,
            0xf, 0x6, 0x1, 0x0, 0x2, 0x7, 0x7, 0xf,
            0x8, 0x5, 0x4, 0xd, 0x1, 0xd, 0xd, 0x6,

            0x9, 0x5, 0x3, 0x1, 0xc, 0xb, 0x5, 0x7,
            0xe, 0x6, 0xb, 0xf, 0xc, 0x6, 0xc, 0x8,
            0xb, 0x1, 0x4, 0xd, 0xa, 0xb, 0xf, 0x1,
            0x7, 0x6, 0xa, 0xa, 0x8, 0xc, 0x6, 0x2,

            0xe, 0x0, 0x5, 0x7, 0x9, 0x3, 0x6, 0x8,
            0xb, 0xf, 0x1, 0xb, 0x5, 0x6, 0xe, 0x4,
            0x0, 0x2, 0x2, 0x4, 0x3, 0xd, 0xc, 0x1,
            0xb, 0xc, 0xa, 0x1, 0x3, 0xa, 0x9, 0x5,
            ].iter().copied()),
        ..Default::default()
    })
    .unwrap();
    println!("Foo...");
    model.step_until_output("state=1 data=97413e2d\n").unwrap();

    model
        .copy_output_until_exit_success(LineWriter::new(stdout()))
        .unwrap();
}
