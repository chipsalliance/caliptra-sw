// Licensed under the Apache-2.0 license

use std::error::Error;

use caliptra_builder::FwId;
use caliptra_drivers_test_bin::DoeTestResults;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, HwModel, InitParams, ModelError, SecurityState,
};
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_test::derive::{DoeInput, DoeOutput};
use openssl::{hash::MessageDigest, pkey::PKey};
use zerocopy::{transmute, AsBytes, FromBytes};

fn build_test_rom(test_bin_name: &'static str) -> Vec<u8> {
    caliptra_builder::build_firmware_rom(&FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: test_bin_name,
        features: &["emu"],
        ..Default::default()
    })
    .unwrap()
}

fn start_driver_test(test_bin_name: &'static str) -> Result<DefaultHwModel, Box<dyn Error>> {
    let rom = build_test_rom(test_bin_name);
    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
}

fn run_driver_test(test_bin_name: &'static str) {
    let mut model = start_driver_test(test_bin_name).unwrap();
    // Wrap in a line-writer so output from different test threads doesn't multiplex within a line.
    model.step_until_exit_success().unwrap();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DoeTestVectors {
    // The keys output by the DOE block (mostly for reference)
    doe_output: DoeOutput,

    // The expected results of the HMAC operations performed by the test.
    expected_test_results: DoeTestResults,
}
impl DoeTestVectors {
    /// A standalone implementation of the cryptographic operations necessary to
    /// generate the expected DOE test's HMAC results from fuse values and
    /// silicon secrets, using only openssl. This independent implementation is
    /// used to validate that the test-vector constants are correct.
    fn generate(input: &DoeInput) -> Self {
        use openssl::sign::Signer;

        fn swap_word_bytes(words: &[u32]) -> Vec<u32> {
            words.iter().map(|word| word.swap_bytes()).collect()
        }
        fn swap_word_bytes_inplace(words: &mut [u32]) {
            for word in words.iter_mut() {
                *word = word.swap_bytes()
            }
        }
        fn hmac384(key: &[u8], data: &[u8]) -> [u8; 48] {
            let pkey = PKey::hmac(key).unwrap();
            let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
            signer.update(data).unwrap();
            let mut result = [0u8; 48];
            signer.sign(&mut result).unwrap();
            result
        }

        let mut result = DoeTestVectors {
            doe_output: DoeOutput::generate(input),
            expected_test_results: Default::default(),
        };

        result.expected_test_results.hmac_uds_as_key = transmute!(hmac384(
            swap_word_bytes(&result.doe_output.uds).as_bytes(),
            "Hello world!".as_bytes()
        ));
        swap_word_bytes_inplace(&mut result.expected_test_results.hmac_uds_as_key);

        result.expected_test_results.hmac_uds_as_data = transmute!(hmac384(
            swap_word_bytes(&caliptra_drivers_test_bin::DOE_TEST_HMAC_KEY).as_bytes(),
            swap_word_bytes(&result.doe_output.uds).as_bytes()
        ));
        swap_word_bytes_inplace(&mut result.expected_test_results.hmac_uds_as_data);

        result.expected_test_results.hmac_field_entropy_as_key = transmute!(hmac384(
            swap_word_bytes(&result.doe_output.field_entropy).as_bytes(),
            "Hello world!".as_bytes()
        ));
        swap_word_bytes_inplace(&mut result.expected_test_results.hmac_field_entropy_as_key);

        result.expected_test_results.hmac_field_entropy_as_data = transmute!(hmac384(
            swap_word_bytes(&caliptra_drivers_test_bin::DOE_TEST_HMAC_KEY).as_bytes(),
            swap_word_bytes(&result.doe_output.field_entropy[0..8]).as_bytes()
        ));
        swap_word_bytes_inplace(&mut result.expected_test_results.hmac_field_entropy_as_data);
        result
    }
}

const DOE_TEST_VECTORS_DEBUG_MODE: DoeTestVectors = DoeTestVectors {
    doe_output: DoeOutput {
        // The decrypted UDS as stored in the key vault
        uds: [
            0x34aa667c, 0x0a52c71f, 0x977a1de2, 0x701ef611, 0x0de19e21, 0x24b49b9d, 0xdf205ff6,
            0xa9c04303, 0x0de19e21, 0x24b49b9d, 0xdf205ff6, 0xa9c04303,
        ],

        // The decrypted field entropy as stored in the key vault (with padding)
        field_entropy: [
            0x34aa667c,
            0x0a52c71f,
            0x977a1de2,
            0x701ef611,
            0x0de19e21,
            0x24b49b9d,
            0xdf205ff6,
            0xa9c04303,
            0xaaaa_aaaa,
            0xaaaa_aaaa,
            0xaaaa_aaaa,
            0xaaaa_aaaa,
        ],
    },

    // The expected results of the HMAC operations performed by the test.
    expected_test_results: DoeTestResults {
        hmac_uds_as_key: [
            0x4446d380, 0xd2cb5d96, 0xcf745d40, 0xbfe7dcdb, 0x58a8befe, 0x2ddc1eac, 0xbc93b36c,
            0xccc277ab, 0xedc67ae7, 0x7e4e12a4, 0x106e0e34, 0xb065b021,
        ],
        hmac_uds_as_data: [
            0xe507101b, 0xb5fc57e0, 0xa02d2cdf, 0xb5b4d5ba, 0x69535616, 0xcb9d3ab8, 0x5a571a66,
            0xb5e76d47, 0x802e86ba, 0x2969e838, 0x36869873, 0xb6847c27,
        ],
        hmac_field_entropy_as_key: [
            0x683285f1, 0x27d26fc8, 0xe9e716c2, 0x0dc9c7fb, 0x9cad8b4c, 0xaeb167c5, 0xb402cf3b,
            0x2e2c1745, 0x560bb884, 0xf592628f, 0x66db5c8f, 0x883086eb,
        ],
        hmac_field_entropy_as_data: [
            0x4d2aec76, 0x7c73efbe, 0xb50aa67c, 0x89a684e3, 0x823834c4, 0x3429dea2, 0xf35cfdb0,
            0xbfef4e6a, 0xa40dc572, 0xea82be07, 0xc93ef76a, 0xf955f845,
        ],
    },
};

#[test]
fn test_generate_doe_vectors_when_debug_not_locked() {
    // When microcontroller debugging is possible, all the secrets are set by the hardware to
    // 0xffff_ffff words.
    let vectors = DoeTestVectors::generate(&DoeInput {
        doe_obf_key: [0xffff_ffff_u32; 8],

        doe_uds_iv: caliptra_drivers_test_bin::DOE_TEST_IV,
        doe_fe_iv: caliptra_drivers_test_bin::DOE_TEST_IV,

        uds_seed: [0xffff_ffff_u32; 12],
        field_entropy_seed: [0xffff_ffff_u32; 8],

        // In debug mode, this defaults to 0xaaaa_aaaa
        keyvault_initial_word_value: 0xaaaa_aaaa,
    });
    assert_eq!(vectors, DOE_TEST_VECTORS_DEBUG_MODE);
}

#[test]
fn test_doe_when_debug_not_locked() {
    let rom = build_test_rom("doe");
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: *SecurityState::from(0)
                .set_debug_locked(false)
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    let txn = model.wait_for_mailbox_receive().unwrap();
    let test_results = DoeTestResults::read_from(txn.req.data.as_slice()).unwrap();
    assert_eq!(
        test_results,
        DOE_TEST_VECTORS_DEBUG_MODE.expected_test_results
    )
}

const DOE_TEST_VECTORS: DoeTestVectors = DoeTestVectors {
    doe_output: DoeOutput {
        uds: [
            0x0b21f10f, 0x6963005e, 0x4884d93f, 0x1f91037a, 0x2d37ffe0, 0x3727b5e8, 0xb78b9608,
            0x7e0e58d2, 0x420ce5ae, 0x4b1f04f8, 0x33b7af81, 0x72156bd8,
        ],
        field_entropy: [
            0x3d75d35e, 0xbc44a31e, 0xad27aee5, 0x75cdd170, 0xe51dcaf4, 0x09c096ae, 0xa70ff448,
            0x64834722, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        ],
    },
    expected_test_results: DoeTestResults {
        hmac_uds_as_key: [
            0xf1e6eebe, 0x17718892, 0x6b3482a4, 0x6ebdd31a, 0x1a64b1df, 0xf832d618, 0x5d209aeb,
            0x3e22c6a5, 0xaf18b9da, 0x78767e58, 0x143b5932, 0xb94caa30,
        ],
        hmac_uds_as_data: [
            0x255b90d3, 0xce58a455, 0x72ca9fbb, 0xb6f963b8, 0x8a9e809c, 0x101dadf8, 0x1e35d99c,
            0x459e5648, 0x44ad895a, 0x6342b793, 0x73b5d82a, 0xa65a9e8a,
        ],
        hmac_field_entropy_as_key: [
            0x4c904ff4, 0xe1b642b7, 0xdaf61d5c, 0x0ae649ad, 0x22411ddd, 0x288e0902, 0x2911effc,
            0xd76b38f1, 0x0c6ea42e, 0xd1b53612, 0xf77d2515, 0x954d9088,
        ],
        hmac_field_entropy_as_data: [
            0x9f6024ff, 0x68fd825a, 0xbad1ce52, 0x18ed486d, 0x4dd1edc2, 0xeacfeb0b, 0x8d5d8873,
            0x896be4f5, 0x8f30e6fa, 0xcc1b11c3, 0x0df0bc6e, 0x8fa6b5ba,
        ],
    },
};

#[test]
fn test_generate_doe_vectors_when_debug_locked() {
    let vectors = DoeTestVectors::generate(&DoeInput {
        doe_obf_key: caliptra_hw_model_types::DEFAULT_CPTRA_OBF_KEY,

        doe_uds_iv: caliptra_drivers_test_bin::DOE_TEST_IV,
        doe_fe_iv: caliptra_drivers_test_bin::DOE_TEST_IV,

        uds_seed: caliptra_hw_model_types::DEFAULT_UDS_SEED,
        field_entropy_seed: caliptra_hw_model_types::DEFAULT_FIELD_ENTROPY,

        // in debug-locked mode, this defaults to 0
        keyvault_initial_word_value: 0x0000_0000,
    });
    assert_eq!(DOE_TEST_VECTORS, vectors);
}

#[test]
fn test_doe_when_debug_locked() {
    let rom = build_test_rom("doe");
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: *SecurityState::from(0)
                .set_debug_locked(true)
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    let txn = model.wait_for_mailbox_receive().unwrap();
    let test_results = DoeTestResults::read_from(txn.req.data.as_slice()).unwrap();
    assert_eq!(test_results, DOE_TEST_VECTORS.expected_test_results)
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
            Err(ModelError::MailboxCmdFailed(0))
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
fn test_mailbox_uc_to_soc() {
    let mut model = start_driver_test("mailbox_driver_sender").unwrap();

    // 0 byte request
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xa000_0000);
    assert_eq!(txn.req.data, b"");
    txn.respond_success();

    // 3 byte request
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xa000_1000);
    assert_eq!(txn.req.data, b"Hi!");
    // NOTE: The current driver doesn't actually look at the result
    txn.respond_success();

    // 4 byte request
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xa000_2000);
    assert_eq!(txn.req.data, b"Hi!!");
    txn.respond_success();

    // 6 byte request
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xa000_3000);
    assert_eq!(txn.req.data, b"Hello!");
    txn.respond_success();

    // 8 byte request
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xa000_4000);
    assert_eq!(txn.req.data, b"Hello!!!");
    txn.respond_success();

    // write_cmd / write_dlen / execute_request used separately
    let txn = model.wait_for_mailbox_receive().unwrap();
    assert_eq!(txn.req.cmd, 0xb000_0000);
    assert_eq!(txn.req.data, b"");
    txn.respond_success();
}

#[test]
fn test_mailbox_negative_tests() {
    let mut model = start_driver_test("mailbox_driver_negative_tests").unwrap();
    let txn = model.wait_for_mailbox_receive().unwrap();

    let cmd = txn.req.cmd;

    // Test the receiver can't change the command register when the FSM is in Exec state.
    assert!(model.soc_mbox().cmd().read() == cmd);
    model.soc_mbox().cmd().write(|_| cmd + 1);
    assert!(model.soc_mbox().cmd().read() == cmd);

    // Check we can't release the lock on the receiver side.
    model.soc_mbox().execute().write(|w| w.execute(false));

    assert!(model
        .soc_mbox()
        .status()
        .read()
        .mbox_fsm_ps()
        .mbox_execute_soc());

    // Finally, respond :
    model
        .soc_mbox()
        .status()
        .write(|w| w.status(|_| MboxStatusE::DataReady));
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
fn test_csrng() {
    // https://github.com/chipsalliance/caliptra-rtl/blob/fa91d66f30223899403f4e65a6f697a6f9100fd1/src/csrng/tb/csrng_tb.sv#L461
    const TRNG_ENTROPY: &str = "33F63B65F57AD68765693560E743CC5010518E4BF4ECBEBA71DC56AAA08B394311731D9DF763FC5D27E4ED3E4B7DE947";

    let rom = caliptra_builder::build_firmware_rom(&FwId {
        crate_name: "caliptra-drivers-test-bin",
        bin_name: "csrng",
        features: &["emu"],
        ..Default::default()
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
