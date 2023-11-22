// Licensed under the Apache-2.0 license.

use crate::common::run_rt_test;
use caliptra_common::mailbox_api::{HmacVerifyReq, MailboxReqHeader};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError};

#[test]
fn hmac_cmd_run_wycheproof() {
    let mut model = run_rt_test(None, None, None);

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
            let req = HmacVerifyReq {
                hdr: MailboxReqHeader { chksum: 0 },
                key: test.key[..].try_into().unwrap(),
                tag: test.tag[..].try_into().unwrap(),
                len: test.msg.len().try_into().unwrap(),
                msg,
            };
            let resp = model.mailbox_execute_req(req);

            const RUNTIME_HMAC_VERIFY_FAILED: u32 =
                CaliptraError::RUNTIME_HMAC_VERIFY_FAILED.0.get();
            match test.result {
                wycheproof::TestResult::Valid | wycheproof::TestResult::Acceptable => match resp {
                    Err(ModelError::MailboxCmdFailed(RUNTIME_HMAC_VERIFY_FAILED)) => {
                        wyche_fail.push(WycheproofResults {
                            id: test.tc_id,
                            comment: test.comment.to_string(),
                        });
                    }
                    Ok(_) => {
                        // Expected result
                    }
                    Err(e) => panic!("{e}"),
                },
                wycheproof::TestResult::Invalid => match resp {
                    Ok(_) => {
                        wyche_fail.push(WycheproofResults {
                            id: test.tc_id,
                            comment: test.comment.to_string(),
                        });
                    }
                    Err(ModelError::MailboxCmdFailed(RUNTIME_HMAC_VERIFY_FAILED)) => {
                        // Expected result
                    }
                    Err(e) => panic!("{e}"),
                },
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
