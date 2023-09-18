// Licensed under the Apache-2.0 license.
pub mod common;

use caliptra_common::mailbox_api::{
    CommandId, EcdsaVerifyReq, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::{HwModel, ShaAccMode};
use caliptra_runtime::RtBootStatus;
use common::run_rt_test;
use zerocopy::{AsBytes, FromBytes};

// This file includes some tests from Wycheproof to testing specific common
// ECDSA problems.
// In the long term, this file should just run the entire Wycheproof test
// vector file wycheproof/testvectors_v1/ecdsa_secp384r1_sha384_test.json

#[test]
fn ecdsa_cmd_run_wycheproof() {
    let mut model = run_rt_test(None, None);

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

            let cmd = EcdsaVerifyReq {
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
            };
            let checksum = caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::ECDSA384_VERIFY),
                &cmd.as_bytes()[4..],
            );
            let cmd = EcdsaVerifyReq {
                hdr: MailboxReqHeader { chksum: checksum },
                ..cmd
            };
            let resp = model.mailbox_execute(u32::from(CommandId::ECDSA384_VERIFY), cmd.as_bytes());
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
