// Licensed under the Apache-2.0 license.
pub mod common;

use caliptra_common::mailbox_api::{CommandId, HmacVerifyReq, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::HwModel;
use common::run_rt_test;
use zerocopy::{AsBytes, FromBytes};

#[test]
fn hmac_cmd_run_wycheproof() {
    let mut model = run_rt_test(None);

    model
        .step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();

    #[allow(dead_code)]
    #[derive(Debug)]
    struct WycheproofResults {
        id: usize,
        comment: String,
    }

    // Collect all the errors and print at the end
    let mut wyche_fail: Vec<WycheproofResults> = Vec::new();
    let mut wyche_ran: Vec<WycheproofResults> = Vec::new();
    let test_set = wycheproof::mac::TestSet::load(wycheproof::mac::TestName::HmacSha384).unwrap();

    for test_groups in test_set.test_groups {
        for test in &test_groups.tests {
            // The mailbox is only implemented for keys and tags of 384 bits
            if test.key.len() != 48 || test.tag.len() != 48 {
                continue;
            }
            wyche_ran.push(WycheproofResults {
                id: test.tc_id,
                comment: test.comment.to_string(),
            });
            let mut msg = [0; 256];
            msg[..test.msg.len()].copy_from_slice(test.msg.as_slice());
            let cmd = HmacVerifyReq {
                hdr: MailboxReqHeader { chksum: 0 },
                key: test.key[..].try_into().unwrap(),
                tag: test.tag[..].try_into().unwrap(),
                len: test.msg.len().try_into().unwrap(),
                msg,
            };
            let checksum = caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
                &cmd.as_bytes()[4..],
            );
            let cmd = HmacVerifyReq {
                hdr: MailboxReqHeader { chksum: checksum },
                ..cmd
            };
            let resp = model.mailbox_execute(
                u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
                cmd.as_bytes(),
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
