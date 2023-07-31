// Licensed under the Apache-2.0 license.
pub mod common;

use caliptra_hw_model::HwModel;
use caliptra_runtime::{CommandId, HmacVerifyCmd};
use common::run_rt_test;
use zerocopy::AsBytes;

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
            let mut cmd = HmacVerifyCmd {
                chksum: 0,
                key: test.key[..].try_into().unwrap(),
                tag: test.tag[..].try_into().unwrap(),
                len: u32::try_from(test.msg.len()).unwrap(),
                msg: [0u8; 256],
            };
            cmd.msg[..test.msg.len()].clone_from_slice(test.msg.as_slice());
            let checksum = caliptra_common::checksum::calc_checksum(
                u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
                &cmd.as_bytes()[4..],
            );
            let cmd = HmacVerifyCmd {
                chksum: checksum,
                ..cmd
            };
            let resp = model.mailbox_execute(
                u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
                cmd.as_bytes(),
            );
            match test.result {
                wycheproof::TestResult::Valid | wycheproof::TestResult::Acceptable => match resp {
                    Err(_) | Ok(Some(_)) => {
                        wyche_fail.push(WycheproofResults {
                            id: test.tc_id,
                            comment: test.comment.to_string(),
                        });
                    }
                    _ => {}
                },
                wycheproof::TestResult::Invalid => {
                    if let Ok(None) = resp {
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
