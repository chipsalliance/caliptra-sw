// Licensed under the Apache-2.0 license

use std::error::Error;

use caliptra_builder::FwId;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams, ModelError};

fn start_driver_test(test_bin_name: &str) -> Result<DefaultHwModel, Box<dyn Error>> {
    let rom = caliptra_builder::build_firmware_rom(&FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: test_bin_name,
        features: &["emu"],
    })
    .unwrap();
    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
}

fn run_driver_test(test_bin_name: &str) {
    let mut model = start_driver_test(test_bin_name).unwrap();
    // Wrap in a line-writer so output from different test threads doesn't multiplex within a line.
    model.step_until_exit_success().unwrap();
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
fn test_mailbox_soc_to_uc() {
    let mut model = start_driver_test("mailbox_driver_responder").unwrap();

    // Test MailboxRecvTxn::recv_request()
    {
        model
            .mailbox_execute(
                0x5000_0000,
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            )
            .unwrap();

        // With recv_request(), the mailbox transaction is completed as
        // successful before the firmware as a chance to look at the buffer (!?),
        // so give the firmware a chance to print it out.
        model
            .step_until_output(
                "cmd: 0x50000000\n\
                 dlen: 8\n\
                 buf: [67452301, efcdab89, 00000000, 00000000]\n",
            )
            .unwrap();
        model.output().take(usize::MAX);

        // Try again, but with a non-multiple-of-4 size
        model
            .mailbox_execute(0x5000_0000, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd])
            .unwrap();
        model
            .step_until_output(
                "cmd: 0x50000000\n\
                 dlen: 7\n\
                 buf: [67452301, 00cdab89, 00000000, 00000000]\n",
            )
            .unwrap();
        model.output().take(usize::MAX);

        // Try again, but with no data in the FIFO
        model.mailbox_execute(0x5000_0000, &[]).unwrap();
        model
            .step_until_output(
                "cmd: 0x50000000\n\
                 dlen: 0\n\
                 buf: [00000000, 00000000, 00000000, 00000000]\n",
            )
            .unwrap();
        model.output().take(usize::MAX);
    }

    // Test MailboxRecvTxn::copy_request
    {
        model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77,
                ],
            )
            .unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 16\n\
             buf: [67452301, efcdab89]\n\
             buf: [33221100, 77665544]\n"
        );

        // Try again, but with a non-multiple-of-4 size
        model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
                ],
            )
            .unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 13\n\
             buf: [67452301, efcdab89]\n\
             buf: [33221100, 00000044]\n"
        );

        // Try again, but where the buffer is larger than the last chunk
        model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33,
                ],
            )
            .unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 12\n\
             buf: [67452301, efcdab89]\n\
             buf: [33221100, 33221100]\n"
        );
        // TODO: It is not optimal that the driver copies the last word in the
        // FIFO to the extra array location.

        // Try again, but with no data in the FIFO
        model.mailbox_execute(0x6000_0000, &[]).unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 0\n"
        );
    }

    // Test MailboxRecvTxn completed with success without draining the FIFO
    {
        model
            .mailbox_execute(0x7000_0000, &[0x88, 0x99, 0xaa, 0xbb])
            .unwrap();
        assert_eq!(model.output().take(usize::MAX), "cmd: 0x70000000\n");

        // Make sure the next command doesn't see the FIFO from the previous command
        model
            .mailbox_execute(0x6000_0000, &[0x07, 0x06, 0x05, 0x04, 0x03])
            .unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 5\n\
             buf: [04050607, 00000003]\n"
        );
    }

    // Test MailboxRecvTxn completed with failure without draining the FIFO
    {
        assert_eq!(
            model.mailbox_execute(0x8000_0000, &[0x88, 0x99, 0xaa, 0xbb]),
            Err(ModelError::MailboxCmdFailed)
        );
        assert_eq!(model.output().take(usize::MAX), "cmd: 0x80000000\n");

        // Make sure the next command doesn't see the FIFO from the previous command
        model
            .mailbox_execute(0x6000_0000, &[0x07, 0x06, 0x05, 0x04, 0x03])
            .unwrap();
        assert_eq!(
            model.output().take(usize::MAX),
            "cmd: 0x60000000\n\
             dlen: 5\n\
             buf: [04050607, 00000003]\n"
        );
    }
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
fn test_lms_24() {
    run_driver_test("test_lms_24");
}

#[test]
fn test_lms_32() {
    run_driver_test("test_lms_32");
}

#[test]
fn test_negative_lms() {
    run_driver_test("test_negative_lms");
}

#[test]
#[cfg(feature = "verilator")]
fn test_csrng() {
    // https://github.com/chipsalliance/caliptra-rtl/blob/fa91d66f30223899403f4e65a6f697a6f9100fd1/src/csrng/tb/csrng_tb.sv#L461
    const TRNG_ENTROPY: &str = "33F63B65F57AD68765693560E743CC5010518E4BF4ECBEBA71DC56AAA08B394311731D9DF763FC5D27E4ED3E4B7DE947";

    let rom = caliptra_builder::build_firmware_rom(&FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "csrng",
        features: &["emu"],
    })
    .unwrap();

    let trng_nibbles = TRNG_ENTROPY
        .chars()
        .rev()
        .map(|b| b.to_digit(16).expect("bad nibble digit") as u8);

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            trng_nibbles: Box::new(trng_nibbles),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    model.step_until_exit_success().unwrap();
}
