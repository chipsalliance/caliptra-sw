// Licensed under the Apache-2.0 license.

use crate::common::{run_rt_test, RuntimeTestArgs};
use caliptra_api::mailbox::{MailboxReq, MailboxReqHeader, MailboxRespHeader, MldsaVerifyReq};
use caliptra_api::SocManager;
use caliptra_common::mailbox_api::CommandId;
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use ml_dsa::signature::Signer;
use ml_dsa::{KeyGen, MlDsa87};
use rand::thread_rng;
use zerocopy::{FromBytes, IntoBytes};

#[test]
fn test_mldsa_verify_cmd() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Generate keypair and sign a message using ml-dsa
    let mut rng = thread_rng();
    let keypair = MlDsa87::key_gen(&mut rng);

    let message = b"Hello, MLDSA verification test!";
    let signature = keypair.signing_key().sign(message);

    // Extract raw bytes for the public key and signature
    let public_key_bytes = keypair.verifying_key().encode();
    let signature_bytes = signature.encode();

    // Pad signature to match expected size (4628 bytes)
    let mut padded_signature = [0u8; 4628];
    padded_signature[..signature_bytes.len()].copy_from_slice(&signature_bytes);

    // Create MLDSA verify request
    let mut cmd = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: padded_signature,
        message_size: message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..message.len()].copy_from_slice(message);
            msg_array
        },
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let resp_hdr: &MailboxRespHeader = MailboxRespHeader::ref_from_bytes(resp.as_bytes()).unwrap();

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Checksum is just going to be 0 because FIPS_STATUS_APPROVED is 0
    assert_eq!(resp_hdr.chksum, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);

    // Test with modified message to ensure signature verification fails
    let mut modified_message = *message;
    modified_message[0] ^= 0x01; // Flip one bit in the first byte

    let mut cmd_fail = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: public_key_bytes.into(),
        signature: padded_signature,
        message_size: modified_message.len() as u32,
        message: {
            let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
            msg_array[..modified_message.len()].copy_from_slice(&modified_message);
            msg_array
        },
    });
    cmd_fail.populate_chksum().unwrap();

    let resp_fail = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd_fail.as_bytes().unwrap(),
        )
        .unwrap_err();

    crate::common::assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_MLDSA_VERIFY_FAILED,
        resp_fail,
    );
}

#[test]
fn test_mldsa_verify_bad_chksum() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let cmd = MailboxReq::MldsaVerify(MldsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key: [0u8; 2592],   // MLDSA87_PUB_KEY_BYTE_SIZE
        signature: [0u8; 4628], // MLDSA87_SIGNATURE_BYTE_SIZE
        message_size: 32,
        message: [0u8; 4096],
    });

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    crate::common::assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM,
        resp,
    );
}

// This file includes some tests from Wycheproof to testing specific common
// MLDSA problems.
// In the long term, this file should just run the entire Wycheproof test
// vector file wycheproof/testvectors_v1/mldsa_verify_schema.json

#[test]
fn mldsa_cmd_run_wycheproof() {
    // This test is too slow to run as part of the verilator nightly.
    #![cfg_attr(all(not(feature = "slow_tests"), feature = "verilator"), ignore)]

    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read()
            == <RtBootStatus as Into<u32>>::into(RtBootStatus::RtReadyForCommands)
    });

    #[allow(dead_code)]
    #[derive(Debug)]
    struct WycheproofResults {
        id: usize,
        comment: String,
    }
    // Collect all the errors and print at the end
    let mut wyche_fail: Vec<WycheproofResults> = Vec::new();
    let mut wyche_ran: Vec<WycheproofResults> = Vec::new();

    // Load MLDSA87 verify test set
    let test_set =
        wycheproof::mldsa_verify::TestSet::load(wycheproof::mldsa_verify::TestName::MlDsa87Verify)
            .unwrap();

    for test_group in &test_set.test_groups {
        for test in &test_group.tests {
            // Skip tests with context since Caliptra MLDSA doesn't support context
            if test.ctx.is_some() {
                continue;
            }

            // Check that public key is exactly the right size
            if test_group.pubkey.as_slice().len() != 2592 {
                continue;
            }

            // Check that signature is the right size
            // MLDSA signatures are 4627 bytes, but get padded to 4628 for the mailbox
            // So accept either 4627 or 4628 byte signatures
            let sig_len = test.sig.as_slice().len();
            if sig_len != 4627 {
                continue;
            }

            // Check that message is not too large
            if test.msg.as_slice().len() > 4096 {
                continue;
            }

            wyche_ran.push(WycheproofResults {
                id: test.tc_id,
                comment: test.comment.to_string(),
            });

            // Create MLDSA verify request
            let mut cmd = MailboxReq::MldsaVerify(MldsaVerifyReq {
                hdr: MailboxReqHeader { chksum: 0 },
                pub_key: test_group.pubkey.as_slice()[..].try_into().unwrap(),
                signature: {
                    let sig_slice = test.sig.as_slice();
                    let mut signature = [0u8; 4628]; // MLDSA87_SIGNATURE_BYTE_SIZE
                                                     // Pad 4627-byte signature to 4628 bytes
                    signature[..4627].copy_from_slice(sig_slice);
                    signature
                },
                message_size: test.msg.as_slice().len() as u32,
                message: {
                    let mut msg_array = [0u8; 4096]; // MAX_CMB_DATA_SIZE
                    msg_array[..test.msg.as_slice().len()].copy_from_slice(test.msg.as_slice());
                    msg_array
                },
            });
            cmd.populate_chksum().unwrap();

            let resp = model.mailbox_execute(
                u32::from(CommandId::MLDSA87_SIGNATURE_VERIFY),
                cmd.as_bytes().unwrap(),
            );

            match test.result {
                wycheproof::TestResult::Valid | wycheproof::TestResult::Acceptable => match resp {
                    Err(_) | Ok(None) => {
                        wyche_fail.push(WycheproofResults {
                            id: test.tc_id,
                            comment: test.comment.to_string(),
                        });
                    }
                    Ok(Some(resp)) => {
                        // Verify the checksum and FIPS status
                        let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
                        assert_eq!(
                            resp_hdr.fips_status,
                            MailboxRespHeader::FIPS_STATUS_APPROVED
                        );
                        // Checksum is just going to be 0 because FIPS_STATUS_APPROVED is 0
                        assert_eq!(resp_hdr.chksum, 0);
                    }
                },
                wycheproof::TestResult::Invalid => {
                    if resp.is_ok() {
                        wyche_fail.push(WycheproofResults {
                            id: test.tc_id,
                            comment: test.comment.to_string(),
                        });
                    }
                }
            }
        }
    }
    println!("Executed wycheproof tests:\n{:#?}", wyche_ran);
    if !wyche_fail.is_empty() {
        panic!(
            "Number of failed tests {}:\n{:#?}",
            wyche_fail.len(),
            wyche_fail
        );
    }
}
