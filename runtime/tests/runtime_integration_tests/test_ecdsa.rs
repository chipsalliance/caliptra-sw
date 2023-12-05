// Licensed under the Apache-2.0 license.

use crate::common::run_rt_test;
use caliptra_common::mailbox_api::{
    CommandId, EcdsaVerifyReq, MailboxReq, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{HwModel, ModelError, ShaAccMode};
use caliptra_runtime::RtBootStatus;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

// This file includes some tests from Wycheproof to testing specific common
// ECDSA problems.
// In the long term, this file should just run the entire Wycheproof test
// vector file wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_test.json

#[test]
fn ecdsa_cmd_run_wycheproof() {
    // This test is too slow to run as part of the verilator nightly.
    #![cfg_attr(all(not(feature = "slow_tests"), feature = "verilator"), ignore)]

    let mut model = run_rt_test(None, None, None);

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
    let test_set =
        wycheproof::ecdsa::TestSet::load(wycheproof::ecdsa::TestName::EcdsaSecp384r1Sha384)
            .unwrap();
    // The mailbox has a fixed len for x and y so filter out untestable cases
    let test_groups = test_set
        .test_groups
        .iter()
        .filter(|x| x.key.affine_x.as_slice().len() <= 48)
        .filter(|x| x.key.affine_y.as_slice().len() <= 48);
    for test_group in test_groups {
        for test in &test_group.tests {
            // Since the mailbox uses R, S as input for signature use only tests with a valid signature
            let Ok(signature) = openssl::ecdsa::EcdsaSig::from_der(test.sig.as_bytes()) else {
                continue;
            };
            if signature.r().to_vec().len() > 48 || signature.s().to_vec().len() > 48 {
                continue;
            }
            // openssl rust crates has problems parsing some DER signatures. Skip those as those can't be
            // sent to the mailbox anyway.
            if [
                "Legacy: ASN encoding of s misses leading 0",
                "length of sequence [r, s] uses long form encoding",
                "length of sequence [r, s] contains a leading 0",
                "appending unused 0's to sequence [r, s]",
                "indefinite length",
                "indefinite length with garbage",
                "length of r uses long form encoding",
                "length of r contains a leading 0",
                "prepending 0's to r",
                "length of s uses long form encoding",
                "length of s contains a leading 0",
                "prepending 0's to s",
            ]
            .contains(&test.comment.as_str())
            {
                continue;
            }

            wyche_ran.push(WycheproofResults {
                id: test.tc_id,
                comment: test.comment.to_string(),
            });
            model
                .compute_sha512_acc_digest(test.msg.as_slice(), ShaAccMode::Sha384Stream)
                .unwrap();

            let mut cmd = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
                hdr: MailboxReqHeader { chksum: 0 },
                pub_key_x: test_group.key.affine_x.as_slice()[..].try_into().unwrap(),
                pub_key_y: test_group.key.affine_y.as_slice()[..].try_into().unwrap(),
                signature_r: signature
                    .r()
                    .to_vec_padded(48)
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                signature_s: signature
                    .s()
                    .to_vec_padded(48)
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                // Do tests on mailbox
            });
            cmd.populate_chksum().unwrap();
            let resp = model.mailbox_execute(
                u32::from(CommandId::ECDSA384_VERIFY),
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
                        let resp_hdr = MailboxRespHeader::read_from(resp.as_slice()).unwrap();
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

#[test]
fn test_ecdsa_verify_cmd() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Message to hash
    let msg: &[u8] = &[
        0x9d, 0xd7, 0x89, 0xea, 0x25, 0xc0, 0x47, 0x45, 0xd5, 0x7a, 0x38, 0x1f, 0x22, 0xde, 0x01,
        0xfb, 0x0a, 0xbd, 0x3c, 0x72, 0xdb, 0xde, 0xfd, 0x44, 0xe4, 0x32, 0x13, 0xc1, 0x89, 0x58,
        0x3e, 0xef, 0x85, 0xba, 0x66, 0x20, 0x44, 0xda, 0x3d, 0xe2, 0xdd, 0x86, 0x70, 0xe6, 0x32,
        0x51, 0x54, 0x48, 0x01, 0x55, 0xbb, 0xee, 0xbb, 0x70, 0x2c, 0x75, 0x78, 0x1a, 0xc3, 0x2e,
        0x13, 0x94, 0x18, 0x60, 0xcb, 0x57, 0x6f, 0xe3, 0x7a, 0x05, 0xb7, 0x57, 0xda, 0x5b, 0x5b,
        0x41, 0x8f, 0x6d, 0xd7, 0xc3, 0x0b, 0x04, 0x2e, 0x40, 0xf4, 0x39, 0x5a, 0x34, 0x2a, 0xe4,
        0xdc, 0xe0, 0x56, 0x34, 0xc3, 0x36, 0x25, 0xe2, 0xbc, 0x52, 0x43, 0x45, 0x48, 0x1f, 0x7e,
        0x25, 0x3d, 0x95, 0x51, 0x26, 0x68, 0x23, 0x77, 0x1b, 0x25, 0x17, 0x05, 0xb4, 0xa8, 0x51,
        0x66, 0x02, 0x2a, 0x37, 0xac, 0x28, 0xf1, 0xbd,
    ];

    // Stream to SHA ACC
    model
        .compute_sha512_acc_digest(msg, ShaAccMode::Sha384Stream)
        .unwrap();

    // ECDSAVS NIST test vector
    let mut cmd = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key_x: [
            0xcb, 0x90, 0x8b, 0x1f, 0xd5, 0x16, 0xa5, 0x7b, 0x8e, 0xe1, 0xe1, 0x43, 0x83, 0x57,
            0x9b, 0x33, 0xcb, 0x15, 0x4f, 0xec, 0xe2, 0x0c, 0x50, 0x35, 0xe2, 0xb3, 0x76, 0x51,
            0x95, 0xd1, 0x95, 0x1d, 0x75, 0xbd, 0x78, 0xfb, 0x23, 0xe0, 0x0f, 0xef, 0x37, 0xd7,
            0xd0, 0x64, 0xfd, 0x9a, 0xf1, 0x44,
        ],
        pub_key_y: [
            0xcd, 0x99, 0xc4, 0x6b, 0x58, 0x57, 0x40, 0x1d, 0xdc, 0xff, 0x2c, 0xf7, 0xcf, 0x82,
            0x21, 0x21, 0xfa, 0xf1, 0xcb, 0xad, 0x9a, 0x01, 0x1b, 0xed, 0x8c, 0x55, 0x1f, 0x6f,
            0x59, 0xb2, 0xc3, 0x60, 0xf7, 0x9b, 0xfb, 0xe3, 0x2a, 0xdb, 0xca, 0xa0, 0x95, 0x83,
            0xbd, 0xfd, 0xf7, 0xc3, 0x74, 0xbb,
        ],
        signature_r: [
            0x33, 0xf6, 0x4f, 0xb6, 0x5c, 0xd6, 0xa8, 0x91, 0x85, 0x23, 0xf2, 0x3a, 0xea, 0x0b,
            0xbc, 0xf5, 0x6b, 0xba, 0x1d, 0xac, 0xa7, 0xaf, 0xf8, 0x17, 0xc8, 0x79, 0x1d, 0xc9,
            0x24, 0x28, 0xd6, 0x05, 0xac, 0x62, 0x9d, 0xe2, 0xe8, 0x47, 0xd4, 0x3c, 0xee, 0x55,
            0xba, 0x9e, 0x4a, 0x0e, 0x83, 0xba,
        ],
        signature_s: [
            0x44, 0x28, 0xbb, 0x47, 0x8a, 0x43, 0xac, 0x73, 0xec, 0xd6, 0xde, 0x51, 0xdd, 0xf7,
            0xc2, 0x8f, 0xf3, 0xc2, 0x44, 0x16, 0x25, 0xa0, 0x81, 0x71, 0x43, 0x37, 0xdd, 0x44,
            0xfe, 0xa8, 0x01, 0x1b, 0xae, 0x71, 0x95, 0x9a, 0x10, 0x94, 0x7b, 0x6e, 0xa3, 0x3f,
            0x77, 0xe1, 0x28, 0xd3, 0xc6, 0xae,
        ],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::ECDSA384_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let resp_hdr: &MailboxRespHeader =
        LayoutVerified::<&[u8], MailboxRespHeader>::new(resp.as_bytes())
            .unwrap()
            .into_ref();

    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );
    // Checksum is just going to be 0 because FIPS_STATUS_APPROVED is 0
    assert_eq!(resp_hdr.chksum, 0);
    assert_eq!(model.soc_ifc().cptra_fw_error_non_fatal().read(), 0);
}

#[test]
fn test_ecdsa_verify_bad_chksum() {
    let mut model = run_rt_test(None, None, None);

    let cmd = MailboxReq::EcdsaVerify(EcdsaVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pub_key_x: [0u8; 48],
        pub_key_y: [0u8; 48],
        signature_r: [0u8; 48],
        signature_s: [0u8; 48],
    });

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::ECDSA384_VERIFY),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_INVALID_CHECKSUM)
    );
}
