// Licensed under the Apache-2.0 license

use std::error::Error;
use std::iter;

use caliptra_builder::{firmware, FwId};
use caliptra_drivers::{Array4x12, Array4xN, Ecc384PubKey};
use caliptra_drivers_test_bin::DoeTestResults;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, HwModel, InitParams, ModelError, SecurityState,
    TrngMode,
};
use caliptra_hw_model_types::EtrngResponse;
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::soc_ifc::{
    meta::{CptraItrngEntropyConfig0, CptraItrngEntropyConfig1},
    regs::{CptraItrngEntropyConfig0WriteVal, CptraItrngEntropyConfig1WriteVal},
};
use caliptra_test::{
    crypto::derive_ecdsa_keypair,
    derive::{DoeInput, DoeOutput},
};
use openssl::{hash::MessageDigest, pkey::PKey};
use ureg::ResettableReg;
use zerocopy::{AsBytes, FromBytes};

fn default_init_params() -> InitParams<'static> {
    InitParams {
        // The test harness doesn't clear memory on startup.
        random_sram_puf: false,
        ..Default::default()
    }
}

fn start_driver_test(test_rom: &'static FwId) -> Result<DefaultHwModel, Box<dyn Error>> {
    let rom = caliptra_builder::build_firmware_rom(test_rom)?;
    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..default_init_params()
        },
        ..Default::default()
    })
}

fn run_driver_test(test_rom: &'static FwId) {
    let mut model = start_driver_test(test_rom).unwrap();
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
        fn hmac384(key: &[u8], data: &[u8]) -> [u8; 48] {
            let pkey = PKey::hmac(key).unwrap();
            let mut signer = Signer::new(MessageDigest::sha384(), &pkey).unwrap();
            signer.update(data).unwrap();
            let mut result = [0u8; 48];
            signer.sign(&mut result).unwrap();
            result
        }
        fn ecdsa_keygen(seed: &[u8]) -> Ecc384PubKey {
            let (_, pub_x, pub_y) = derive_ecdsa_keypair(seed);
            Ecc384PubKey {
                x: Array4x12::from(pub_x),
                y: Array4x12::from(pub_y),
            }
        }

        let mut result = DoeTestVectors {
            doe_output: DoeOutput::generate(input),
            expected_test_results: Default::default(),
        };

        result.expected_test_results.hmac_uds_as_key_out_pub = ecdsa_keygen(&hmac384(
            swap_word_bytes(&result.doe_output.uds).as_bytes(),
            "Hello world!".as_bytes(),
        ));

        result.expected_test_results.hmac_uds_as_data_out_pub = ecdsa_keygen(&hmac384(
            swap_word_bytes(&caliptra_drivers_test_bin::DOE_TEST_HMAC_KEY).as_bytes(),
            swap_word_bytes(&result.doe_output.uds).as_bytes(),
        ));

        result
            .expected_test_results
            .hmac_field_entropy_as_key_out_pub = ecdsa_keygen(&hmac384(
            swap_word_bytes(&result.doe_output.field_entropy).as_bytes(),
            "Hello world!".as_bytes(),
        ));

        result
            .expected_test_results
            .hmac_field_entropy_as_data_out_pub = ecdsa_keygen(&hmac384(
            swap_word_bytes(&caliptra_drivers_test_bin::DOE_TEST_HMAC_KEY).as_bytes(),
            swap_word_bytes(&result.doe_output.field_entropy[0..8]).as_bytes(),
        ));
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
        hmac_uds_as_key_out_pub: Ecc384PubKey {
            x: Array4xN([
                1687789458, 142258272, 2190842666, 3455247989, 3888056521, 676567898, 1336470794,
                2772318121, 1868025422, 1214582545, 729740624, 3009942988,
            ]),
            y: Array4xN([
                1187075527, 1937696016, 725517213, 1501324878, 2274800079, 3298049249, 2385708560,
                2858668788, 4158119455, 4066756829, 2930473191, 2541516328,
            ]),
        },
        hmac_uds_as_data_out_pub: Ecc384PubKey {
            x: Array4xN([
                1188012951, 2101019468, 4151111246, 321995737, 1268508043, 3206177196, 2277418785,
                4218900656, 3094045372, 3331153533, 899404842, 3401413295,
            ]),
            y: Array4xN([
                702032169, 1819712272, 2174275591, 1110824269, 2866416596, 1313004867, 1300179142,
                494318965, 3282077418, 3576834306, 1944338607, 495846318,
            ]),
        },
        hmac_field_entropy_as_key_out_pub: Ecc384PubKey {
            x: Array4xN([
                2239914737, 538068278, 2639025677, 1218690763, 2952038842, 1448164004, 2126938572,
                1397119203, 3400164743, 1553307000, 1579829226, 1671197033,
            ]),
            y: Array4xN([
                3709694348, 821080470, 4215236444, 3339301837, 1042205687, 3394791030, 4205793518,
                3991744897, 1399279513, 2065955491, 4026223323, 2237883749,
            ]),
        },
        hmac_field_entropy_as_data_out_pub: Ecc384PubKey {
            x: Array4xN([
                16127504, 1807623126, 1448292055, 4052217305, 961911699, 747606231, 2311165349,
                1941850149, 1401263727, 2590911470, 4055801696, 960530379,
            ]),
            y: Array4xN([
                1246980440, 861204768, 2361057385, 1637522451, 1778431949, 1653325401, 3260666418,
                2934023501, 2085910263, 534236754, 4209071048, 1469026788,
            ]),
        },
    },
};

#[test]
fn test_generate_doe_vectors_when_debug_not_locked() {
    // When microcontroller debugging is possible, all the secrets are set by the hardware to
    // 0xffff_ffff words.
    let vectors = DoeTestVectors::generate(&DoeInput {
        doe_obf_key: [0xffff_ffff_u32; 8],

        doe_iv: caliptra_drivers_test_bin::DOE_TEST_IV,

        uds_seed: [0xffff_ffff_u32; 12],
        field_entropy_seed: [0xffff_ffff_u32; 8],

        // In debug mode, this defaults to 0xaaaa_aaaa
        keyvault_initial_word_value: 0xaaaa_aaaa,
    });
    assert_eq!(vectors, DOE_TEST_VECTORS_DEBUG_MODE);
}

#[test]
fn test_doe_when_debug_not_locked() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::driver_tests::DOE).unwrap();
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: *SecurityState::from(0)
                .set_debug_locked(false)
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
            ..default_init_params()
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
        hmac_uds_as_key_out_pub: Ecc384PubKey {
            x: Array4xN([
                1178783211, 2409029871, 3242977838, 333888818, 19263069, 1643510496, 1837442823,
                239210134, 2976376890, 240016293, 1829920246, 604673977,
            ]),
            y: Array4xN([
                3252295486, 3312576043, 2990063596, 1387770200, 3920640176, 2062006057, 1799980987,
                899709785, 2852029226, 637830070, 1807068751, 2015236177,
            ]),
        },
        hmac_uds_as_data_out_pub: Ecc384PubKey {
            x: Array4xN([
                3780642049, 3453182999, 1751644139, 920456889, 4050113670, 3873779394, 1297921973,
                3724333193, 605901499, 147322750, 1094142208, 3700945418,
            ]),
            y: Array4xN([
                2845240412, 3607790903, 3082786107, 2959038213, 2725359626, 3735269183, 1394565180,
                1096277179, 3492117743, 640718895, 588857878, 1545505434,
            ]),
        },
        hmac_field_entropy_as_key_out_pub: Ecc384PubKey {
            x: Array4xN([
                4052491145, 4186721582, 3342395483, 1632463994, 3193016662, 2204970242, 3835027544,
                2485671111, 2469363717, 1330346930, 2623488737, 1958899419,
            ]),
            y: Array4xN([
                869015362, 1303913274, 842048451, 2998827085, 1486265410, 3771523089, 3956677016,
                2319947800, 4167697556, 3174143636, 820486910, 130118441,
            ]),
        },
        hmac_field_entropy_as_data_out_pub: Ecc384PubKey {
            x: Array4xN([
                735969067, 3049012269, 857888742, 684684485, 4194103772, 1793570427, 1430366021,
                731826037, 58870749, 3416840020, 1596867363, 2600165352,
            ]),
            y: Array4xN([
                3945293618, 150193248, 768912283, 1992928474, 552325555, 2348526265, 299333051,
                253904886, 3695053587, 1856777670, 4185130766, 2902538852,
            ]),
        },
    },
};

#[test]
fn test_generate_doe_vectors_when_debug_locked() {
    let vectors = DoeTestVectors::generate(&DoeInput {
        doe_obf_key: caliptra_hw_model_types::DEFAULT_CPTRA_OBF_KEY,

        doe_iv: caliptra_drivers_test_bin::DOE_TEST_IV,

        uds_seed: caliptra_hw_model_types::DEFAULT_UDS_SEED,
        field_entropy_seed: caliptra_hw_model_types::DEFAULT_FIELD_ENTROPY,

        // in debug-locked mode, this defaults to 0
        keyvault_initial_word_value: 0x0000_0000,
    });
    assert_eq!(vectors, DOE_TEST_VECTORS);
}

#[test]
fn test_doe_when_debug_locked() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::driver_tests::DOE).unwrap();
    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: *SecurityState::from(0)
                .set_debug_locked(true)
                .set_device_lifecycle(DeviceLifecycle::Unprovisioned),
            ..default_init_params()
        },
        ..Default::default()
    })
    .unwrap();

    let txn = model.wait_for_mailbox_receive().unwrap();
    let test_results = DoeTestResults::read_from(txn.req.data.as_slice()).unwrap();
    assert_eq!(test_results, DOE_TEST_VECTORS.expected_test_results);
    txn.respond_success();
    model.step_until_exit_success().unwrap();
}

#[test]
fn test_ecc384() {
    run_driver_test(&firmware::driver_tests::ECC384);
}

#[test]
fn test_ecc384_sign_validation_failure() {
    let mut model =
        start_driver_test(&firmware::driver_tests::ECC384_SIGN_VALIDATION_FAILURE).unwrap();
    model
        .step_until_output_contains("CFI Panic code=0x01040055")
        .unwrap();
}

#[test]
fn test_error_reporter() {
    run_driver_test(&firmware::driver_tests::ERROR_REPORTER);
}

#[test]
fn test_hmac384() {
    run_driver_test(&firmware::driver_tests::HMAC384);
}

#[test]
fn test_keyvault() {
    run_driver_test(if cfg!(feature = "fpga_realtime") {
        &firmware::driver_tests::KEYVAULT_FPGA
    } else {
        &firmware::driver_tests::KEYVAULT
    });
}

#[test]
fn test_mailbox_soc_to_uc() {
    let mut model = start_driver_test(&firmware::driver_tests::MAILBOX_DRIVER_RESPONDER).unwrap();

    // Test MailboxRecvTxn::recv_request()
    {
        let resp = model
            .mailbox_execute(
                0x5000_0000,
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            )
            .unwrap();

        // With recv_request(), the mailbox transaction is completed as
        // successful before the firmware as a chance to look at the buffer (!?),
        // so give the firmware a chance to print it out.
        model
            .step_until_output_and_take(
                "cmd: 0x50000000\n\
                 dlen: 8\n\
                 buf: [67452301, efcdab89, 00000000, 00000000]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with a non-multiple-of-4 size
        let resp = model
            .mailbox_execute(0x5000_0000, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd])
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x50000000\n\
                 dlen: 7\n\
                 buf: [67452301, 00cdab89, 00000000, 00000000]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with no data in the FIFO
        let resp = model.mailbox_execute(0x5000_0000, &[]).unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x50000000\n\
                 dlen: 0\n\
                 buf: [00000000, 00000000, 00000000, 00000000]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with a non-multiple-of-4 dest buffer (0x5000_0001)
        let resp = model
            .mailbox_execute(0x5000_0001, &[0x01, 0x23, 0x45, 0x67, 0x89])
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x50000001\n\
                 dlen: 5\n\
                 buf: [01, 23, 45, 67, 89]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with one more byte than will fit in the dest buffer
        let resp = model
            .mailbox_execute(0x5000_0001, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab])
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x50000001\n\
                 dlen: 6\n\
                 buf: [01, 23, 45, 67, 89]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with 4 more bytes than will fit in the dest buffer
        let resp = model
            .mailbox_execute(
                0x5000_0001,
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11],
            )
            .unwrap();

        model
            .step_until_output_and_take(
                "cmd: 0x50000001\n\
                 dlen: 9\n\
                 buf: [01, 23, 45, 67, 89]\n",
            )
            .unwrap();
        assert_eq!(resp, None);
    }

    // Test MailboxRecvTxn::copy_request
    {
        let resp = model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77,
                ],
            )
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 16\n\
                 buf: [67452301, efcdab89]\n\
                 buf: [33221100, 77665544]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with a non-multiple-of-4 size
        let resp = model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
                ],
            )
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 13\n\
                 buf: [67452301, efcdab89]\n\
                 buf: [33221100, 00000044]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but where the buffer is larger than the last chunk
        let resp = model
            .mailbox_execute(
                0x6000_0000,
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33,
                ],
            )
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 12\n\
                 buf: [67452301, efcdab89]\n\
                 buf: [33221100, 00000000]\n",
            )
            .unwrap();
        assert_eq!(resp, None);

        // Try again, but with no data in the FIFO
        let resp = model.mailbox_execute(0x6000_0000, &[]).unwrap();

        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 0\n",
            )
            .unwrap();
        assert_eq!(resp, None);
    }

    // Test MailboxRecvTxn completed with success without draining the FIFO
    {
        let resp = model
            .mailbox_execute(0x7000_0000, &[0x88, 0x99, 0xaa, 0xbb])
            .unwrap();

        model
            .step_until_output_and_take("cmd: 0x70000000\n")
            .unwrap();
        assert_eq!(resp, None);

        // Make sure the next command doesn't see the FIFO from the previous command
        let resp = model
            .mailbox_execute(0x6000_0000, &[0x07, 0x06, 0x05, 0x04, 0x03])
            .unwrap();

        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 5\n\
                 buf: [04050607, 00000003]\n",
            )
            .unwrap();
        assert_eq!(resp, None);
    }

    // Test MailboxRecvTxn completed with failure without draining the FIFO
    {
        assert_eq!(
            model.mailbox_execute(0x8000_0000, &[0x88, 0x99, 0xaa, 0xbb]),
            Err(ModelError::MailboxCmdFailed(0))
        );

        model
            .step_until_output_and_take("cmd: 0x80000000\n")
            .unwrap();

        // Make sure the next command doesn't see the FIFO from the previous command
        let resp = model
            .mailbox_execute(0x6000_0000, &[0x07, 0x06, 0x05, 0x04, 0x03])
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x60000000\n\
                 dlen: 5\n\
                 buf: [04050607, 00000003]\n",
            )
            .unwrap();
        assert_eq!(resp, None);
    }

    // Test drop_words
    {
        let resp = model
            .mailbox_execute(
                0x9000_0000,
                &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            )
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0x90000000\n\
                 dlen: 8\n\
                 buf: [08070605]\n",
            )
            .unwrap();
        assert_eq!(resp, None);
    }

    // Test 4 byte response with no request data
    {
        let resp = model.mailbox_execute(0xA000_0000, &[]).unwrap().unwrap();
        model
            .step_until_output_and_take("cmd: 0xa0000000\n")
            .unwrap();
        assert_eq!(resp, [0x12, 0x34, 0x56, 0x78]);
    }

    // Test 2 byte response with request data
    {
        let resp = model
            .mailbox_execute(0xB000_0000, &[0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0xa])
            .unwrap()
            .unwrap();
        model
            .step_until_output_and_take(
                "cmd: 0xb0000000\n\
                 dlen: 6\n\
                 buf: [0c0d0e0f, 00000a0b]\n",
            )
            .unwrap();
        assert_eq!(resp, [0x98, 0x76]);
    }

    // Test 9 byte reponse
    {
        let resp = model.mailbox_execute(0xC000_0000, &[]).unwrap().unwrap();
        model
            .step_until_output_and_take("cmd: 0xc0000000\n")
            .unwrap();
        assert_eq!(resp, [0x0A, 0x0B, 0x0C, 0x0D, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    // Test reponse with 0 bytes (still calls copy_response)
    {
        let resp = model.mailbox_execute(0xD000_0000, &[]).unwrap().unwrap();
        model
            .step_until_output_and_take("cmd: 0xd0000000\n")
            .unwrap();
        assert_eq!(resp, [] as [u8; 0]);
    }
    // Ensure there isn't any unexpected output
    for _i in 0..100000 {
        model.step();
    }
    assert_eq!(model.output().take(usize::MAX), "");
}

#[test]
fn test_mailbox_uc_to_soc() {
    let mut model = start_driver_test(&firmware::driver_tests::MAILBOX_DRIVER_SENDER).unwrap();

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
fn test_uc_to_soc_error_state() {
    // This test requires strict control over timing
    #![cfg_attr(feature = "fpga_realtime", ignore)]

    let mut model =
        start_driver_test(&firmware::driver_tests::MAILBOX_DRIVER_NEGATIVE_TESTS).unwrap();
    let txn = model.wait_for_mailbox_receive().unwrap();

    let cmd = txn.req.cmd;

    // Test the receiver can't change the command register when the FSM is in Exec state.
    assert!(model.soc_mbox().cmd().read() == cmd);
    model.soc_mbox().cmd().write(|_| cmd + 1);
    assert!(model.soc_mbox().cmd().read() == cmd);

    // Check we can't release the lock on the receiver side.
    model.soc_mbox().execute().write(|w| w.execute(false));

    assert!(model.soc_mbox().status().read().mbox_fsm_ps().mbox_error());

    // Try to respond...
    model
        .soc_mbox()
        .status()
        .write(|w| w.status(|_| MboxStatusE::DataReady));

    // But we're still in the error state
    assert!(model.soc_mbox().status().read().mbox_fsm_ps().mbox_error());

    // Wait for the test-case to force unlock the mailbox
    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let _txn = model.wait_for_mailbox_receive().unwrap();
    model.soc_mbox().execute().write(|w| w.execute(true));

    assert!(model.soc_mbox().status().read().mbox_fsm_ps().mbox_error());

    // Wait for the test-case to force unlock the mailbox
    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());
}

#[test]
fn test_pcrbank() {
    run_driver_test(&firmware::driver_tests::PCRBANK);
}

#[test]
fn test_sha1() {
    run_driver_test(&firmware::driver_tests::SHA1);
}

#[test]
fn test_sha256() {
    run_driver_test(&firmware::driver_tests::SHA256);
}

#[test]
fn test_sha384() {
    run_driver_test(&firmware::driver_tests::SHA384);
}

#[test]
fn test_sha384acc() {
    run_driver_test(&firmware::driver_tests::SHA384ACC);
}

#[test]
fn test_status_reporter() {
    run_driver_test(&firmware::driver_tests::STATUS_REPORTER);
}

#[test]
fn test_lms_24() {
    run_driver_test(&firmware::driver_tests::TEST_LMS_24);
}

#[test]
#[cfg_attr(all(any(feature = "verilator", feature = "fpga_realtime"),), ignore)]
fn test_lms_24_hw_latest() {
    run_driver_test(&firmware::driver_tests::TEST_LMS_24_HW_LATEST);
}

#[test]
fn test_lms_32() {
    run_driver_test(&firmware::driver_tests::TEST_LMS_32);
}

#[test]
#[cfg_attr(all(any(feature = "verilator", feature = "fpga_realtime"),), ignore)]
fn test_lms_32_hw_latest() {
    run_driver_test(&firmware::driver_tests::TEST_LMS_32_HW_LATEST);
}

#[test]
fn test_negative_lms() {
    run_driver_test(&firmware::driver_tests::TEST_NEGATIVE_LMS);
}

#[test]
#[cfg_attr(all(any(feature = "verilator", feature = "fpga_realtime"),), ignore)]
fn test_negative_lms_hw_latest() {
    run_driver_test(&firmware::driver_tests::TEST_NEGATIVE_LMS_HW_LATEST);
}

// Return a series of nibbles that won't fail health tests.
// Used for testing the CSRNG's "success paths".
fn trng_nibbles() -> impl Iterator<Item = u8> + Clone {
    // reversed form of
    // https://github.com/chipsalliance/caliptra-rtl/blob/fa91d66f30223899403f4e65a6f697a6f9100fd1/src/csrng/tb/csrng_tb.sv#L461
    // cycled infintely to provide enough entropy bits for FIPS boot-time health checks
    const TRNG_ENTROPY: &str = "749ED7B4E3DE4E72D5CF367FD9D137113493B80AAA65CD17ABEBCE4FB4E8150105CC347E06539656786DA75F56B36F33";

    TRNG_ENTROPY
        .chars()
        .map(|b| b.to_digit(16).expect("bad nibble digit") as u8)
        .cycle()
}

// Helper function to run CSRNG test binaries with specific entropy nibbles.
fn test_csrng_with_nibbles(
    fwid: &FwId<'static>,
    itrng_nibbles: Box<dyn Iterator<Item = u8> + Send>,
) {
    let rom = caliptra_builder::build_firmware_rom(fwid).unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            itrng_nibbles,
            ..default_init_params()
        },
        ..Default::default()
    })
    .unwrap();

    model.step_until_exit_success().unwrap();
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        not(feature = "itrng")
    ),
    ignore
)]
fn test_csrng() {
    test_csrng_with_nibbles(&firmware::driver_tests::CSRNG, Box::new(trng_nibbles()));
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        not(feature = "itrng")
    ),
    ignore
)]
fn test_csrng2() {
    test_csrng_with_nibbles(&firmware::driver_tests::CSRNG2, Box::new(trng_nibbles()));
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        not(feature = "itrng")
    ),
    ignore
)]
fn test_csrng_repetition_count() {
    // Tests for Repetition Count Test (RCT).
    fn test_repcnt_finite_repeats(
        test_fwid: &FwId<'static>,
        repeat: usize,
        soc_repcnt_threshold: Option<CptraItrngEntropyConfig1WriteVal>,
    ) {
        let rom = caliptra_builder::build_firmware_rom(test_fwid).unwrap();

        let itrng_nibbles = Box::new({
            // The boot-time health testing requires two consecutive windows of 2048-bits to
            // pass or fail health tests. So let's set up our windows to begin with the
            // repeated bits followed by known good entropy bits.
            const NUM_TEST_WINDOW_NIBBLES: usize = 2048 / 4;
            let num_good_entropy_nibbles = NUM_TEST_WINDOW_NIBBLES.saturating_sub(repeat + 2);

            iter::repeat(0b1111)
                .take(repeat)
                .chain(iter::once(0b0000)) // Break repetition
                .chain(trng_nibbles().take(num_good_entropy_nibbles))
                .chain(iter::once(0b0000)) // Break repetition
                .cycle()
        });

        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                itrng_nibbles,
                ..default_init_params()
            },
            initial_repcnt_thresh_reg: soc_repcnt_threshold,
            ..Default::default()
        })
        .unwrap();

        model.step_until_exit_success().unwrap();
    }

    // The following tests assumes the CSRNG driver will use this default threshold value.
    const THRESHOLD: usize = 41;
    const PASS: &FwId = &firmware::driver_tests::CSRNG_PASS_HEALTH_TESTS;
    const FAIL: &FwId = &firmware::driver_tests::CSRNG_FAIL_REPCNT_TESTS;

    // Bits that repeat up to (but excluding) the threshold times should PASS the RCT.
    test_repcnt_finite_repeats(PASS, THRESHOLD - 1, None);

    // Bits that repeat at least threshold times should FAIL the RCT.
    test_repcnt_finite_repeats(FAIL, THRESHOLD, None);

    // If at least one RNG wire has a stuck bit, RCT should fail.
    test_csrng_with_nibbles(FAIL, Box::new(iter::repeat(0b1111)));
    test_csrng_with_nibbles(FAIL, Box::new(iter::repeat(0b0000)));
    test_csrng_with_nibbles(
        FAIL,
        Box::new({
            // The third bit is stuck at zero.
            [0b1011, 0b1010, 0b1000, 0b0000].into_iter().cycle()
        }),
    );

    {
        // Test finite repeats again, but this time, exercise the logic to read and set thresholds from
        // SoC registers.
        const THRESHOLD: usize = 20;
        let soc_repcnt_threshold = Some(
            CptraItrngEntropyConfig1WriteVal::from(CptraItrngEntropyConfig1::RESET_VAL)
                .repetition_count(THRESHOLD as u32),
        );
        test_repcnt_finite_repeats(PASS, THRESHOLD - 1, soc_repcnt_threshold);
        test_repcnt_finite_repeats(FAIL, THRESHOLD, soc_repcnt_threshold);
    }
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        not(feature = "itrng")
    ),
    ignore
)]
fn test_csrng_adaptive_proportion() {
    // Tests for Adaptive Proportion health check.
    // Assumes the CSRNG configures the adaptive proportion's LO and HI
    // thresholds to 25% and 75% of the FIPS health window size, i.e.,
    // 512 and 1536 respectively for a 2048 bit window size.

    // The adaptive proportion test will pass if the number of 1's in a 2048 bit window is in the
    // range [512, 1536]. Note, inclusive bounds
    const PASS: &FwId = &firmware::driver_tests::CSRNG_PASS_HEALTH_TESTS;

    // 512 ones; 1536 zeros - should pass inclusive LO threshold.
    test_csrng_with_nibbles(
        PASS,
        Box::new({
            const WINDOW: [u8; 512] = *include_bytes!("test_data/csrng/512_ones_1536_zeros");
            // Boot-time health checks require testing two 2048 bit windows.
            WINDOW.into_iter().chain(WINDOW)
        }),
    );

    // 1536 ones; 512 zeros - should pass inclusive HI threshold.
    test_csrng_with_nibbles(
        PASS,
        Box::new({
            const WINDOW: [u8; 512] = *include_bytes!("test_data/csrng/1536_ones_512_zeros");
            WINDOW.into_iter().chain(WINDOW)
        }),
    );

    // Otherwise, the test will fail if the number of 1's falls below the LO threshold or exceeds
    // the HI threshold.
    const FAIL: &FwId = &firmware::driver_tests::CSRNG_FAIL_ADAPTP_TESTS;

    // 511 ones; 1537 zeros - should fail LO threshold.
    test_csrng_with_nibbles(
        FAIL,
        Box::new({
            const WINDOW: [u8; 512] = *include_bytes!("test_data/csrng/511_ones_1537_zeros");
            WINDOW.into_iter().chain(WINDOW)
        }),
    );

    // 1537 ones; 511 zeros - should fail HI threshold.
    test_csrng_with_nibbles(
        FAIL,
        Box::new({
            const WINDOW: [u8; 512] = *include_bytes!("test_data/csrng/1537_ones_511_zeros");
            WINDOW.into_iter().chain(WINDOW)
        }),
    );

    // Test the logic of reading thresholds from SoC registers.
    // The SoC will set the HI and LO thresholds to 1224 and 824 respectively (+- 200 of 1024,
    // which is half the test window size).
    fn test_with_soc_threshold(test_fwid: &'static FwId, window: &'static [u8; 512]) {
        const HI_THRESHOLD: u32 = 1224;
        const LO_THRESHOLD: u32 = 824;

        let rom = caliptra_builder::build_firmware_rom(test_fwid).unwrap();
        let itrng_nibbles = Box::new(window.iter().chain(window).copied());
        let threshold_reg =
            CptraItrngEntropyConfig0WriteVal::from(CptraItrngEntropyConfig0::RESET_VAL)
                .high_threshold(HI_THRESHOLD)
                .low_threshold(LO_THRESHOLD);

        let mut model = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                itrng_nibbles,
                ..default_init_params()
            },
            initial_adaptp_thresh_reg: Some(threshold_reg),
            ..Default::default()
        })
        .unwrap();

        model.step_until_exit_success().unwrap();
    }

    // 824 ones; 1224 zeros - should pass inclusive LO threshold.
    test_with_soc_threshold(PASS, include_bytes!("test_data/csrng/824_ones_1224_zeros"));

    // 1224 ones; 824 zeros - should pass inclusive HI threshold.
    test_with_soc_threshold(PASS, include_bytes!("test_data/csrng/1224_ones_824_zeros"));

    // 823 ones; 1225 zeros - should fail LO threshold.
    test_with_soc_threshold(FAIL, include_bytes!("test_data/csrng/823_ones_1225_zeros"));

    // 1225 ones; 823 zeros - should fail HI threshold.
    test_with_soc_threshold(FAIL, include_bytes!("test_data/csrng/1225_ones_823_zeros"));
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        not(feature = "itrng")
    ),
    ignore
)]
fn test_trng_in_itrng_mode() {
    // To run this test under verilator, use --features=verilator,itrng
    let rom = caliptra_builder::build_firmware_rom(&firmware::driver_tests::TRNG_DRIVER_RESPONDER)
        .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            itrng_nibbles: Box::new(trng_nibbles()),
            trng_mode: Some(TrngMode::Internal),
            ..default_init_params()
        },
        ..Default::default()
    })
    .unwrap();

    let trng_block = model.mailbox_execute(0, &[]).unwrap();
    assert_eq!(
        trng_block,
        Some(vec![
            0x2f, 0x3c, 0x3d, 0xca, 0x53, 0xdb, 0x2a, 0x55, 0x5d, 0x9c, 0x74, 0xa9, 0xc3, 0xe4,
            0xbb, 0xda, 0x53, 0x3b, 0x75, 0xcc, 0x22, 0xf0, 0x86, 0xe0, 0xda, 0xd9, 0x55, 0x13,
            0x37, 0xe5, 0xc3, 0x69, 0x77, 0x65, 0xe6, 0x7e, 0x4d, 0x7b, 0x5a, 0xca, 0x16, 0xe6,
            0x7e, 0x1f, 0xaa, 0xd8, 0x5c, 0x9a,
        ])
    );

    let trng_block = model.mailbox_execute(0, &[]).unwrap();
    assert_eq!(
        trng_block,
        Some(vec![
            0x96, 0xf0, 0x63, 0x7d, 0x79, 0xb9, 0xc, 0xfd, 0x84, 0x7e, 0x5e, 0x7b, 0x68, 0x6, 0xc9,
            0x7c, 0x90, 0xdc, 0xde, 0x26, 0x63, 0x7d, 0x4, 0xcd, 0x98, 0x47, 0x79, 0x87, 0x97,
            0x88, 0xfe, 0x2, 0xcd, 0xe8, 0xed, 0x1e, 0xe8, 0x10, 0x4b, 0xce, 0x93, 0xca, 0x24,
            0xba, 0x80, 0xc2, 0x41, 0xae,
        ])
    );
}

#[test]
#[cfg_attr(
    all(
        any(feature = "verilator", feature = "fpga_realtime"),
        feature = "itrng"
    ),
    ignore
)]
fn test_trng_in_etrng_mode() {
    let block0: [u32; 12] = [
        0x65b11c74, 0xd4bd4965, 0x5031ec6a, 0x2deaad1e, 0xc0c5508f, 0xe7258dc9, 0xa0af9e7f,
        0x43e173f0, 0xc614d147, 0x3a31be1b, 0x91227cd7, 0xfe61ed6c,
    ];
    let block1: [u32; 12] = [
        0x6e0780e0, 0x7f7e7385, 0xe43d14bb, 0x07faf8da, 0x0553a88e, 0x4b6bf699, 0x6e09b53a,
        0x5d9c55c8, 0x0303cff9, 0xb9255124, 0x91f478c5, 0xdd186bc8,
    ];

    let rom = caliptra_builder::build_firmware_rom(&firmware::driver_tests::TRNG_DRIVER_RESPONDER)
        .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            itrng_nibbles: Box::new([].iter().copied()),
            etrng_responses: Box::new(
                vec![
                    EtrngResponse {
                        delay: 10,
                        data: block0,
                    },
                    EtrngResponse {
                        delay: 20,
                        data: block1,
                    },
                ]
                .into_iter(),
            ),
            trng_mode: Some(TrngMode::External),
            ..default_init_params()
        },
        ..Default::default()
    })
    .unwrap();

    let trng_block = model.mailbox_execute(0, &[]).unwrap();
    assert_eq!(trng_block, Some(block0.as_bytes().to_vec()));

    let trng_block = model.mailbox_execute(0, &[]).unwrap();
    assert_eq!(trng_block, Some(block1.as_bytes().to_vec()));
}

#[test]
fn test_persistent() {
    run_driver_test(&firmware::driver_tests::PERSISTENT);
}

#[test]
fn test_uart() {
    let mut model = start_driver_test(&firmware::driver_tests::TEST_UART).unwrap();

    let mut output = Vec::new();
    model.copy_output_until_exit_success(&mut output).unwrap();
    assert_eq!(&output, b"aaaaaahello");
}

#[test]
fn test_mailbox_txn_drop() {
    run_driver_test(&firmware::driver_tests::MBOX_SEND_TXN_DROP);
}
