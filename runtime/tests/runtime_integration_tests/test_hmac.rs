// Licensed under the Apache-2.0 license.

use crate::common::run_rt_test;
use caliptra_common::mailbox_api::{
    CommandId, HmacVerifyReq, MailboxReq, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

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
            let mut cmd = MailboxReq::TestHmacVerify(HmacVerifyReq {
                hdr: MailboxReqHeader { chksum: 0 },
                key: test.key[..].try_into().unwrap(),
                tag: test.tag[..].try_into().unwrap(),
                len: test.msg.len().try_into().unwrap(),
                msg,
            });
            cmd.populate_chksum().unwrap();
            let resp = model.mailbox_execute(
                u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
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
fn test_hmac_verify_cmd() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // HMAC-SHA384 NIST test vector
    let nist_key = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    ];
    let mut key = [0u8; 48];
    key[..nist_key.len()].copy_from_slice(&nist_key);

    let nist_msg = [
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    ];
    let mut msg = [0u8; 256];
    msg[..nist_msg.len()].copy_from_slice(&nist_msg);

    let mut cmd = MailboxReq::TestHmacVerify(HmacVerifyReq {
        hdr: MailboxReqHeader { chksum: 0 },
        key,
        tag: [
            0x3e, 0x8a, 0x69, 0xb7, 0x78, 0x3c, 0x25, 0x85, 0x19, 0x33, 0xab, 0x62, 0x90, 0xaf,
            0x6c, 0xa7, 0x7a, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9c, 0xc5, 0x57, 0x7c, 0x6e,
            0x1f, 0x57, 0x3b, 0x4e, 0x68, 0x01, 0xdd, 0x23, 0xc4, 0xa7, 0xd6, 0x79, 0xcc, 0xf8,
            0xa3, 0x86, 0xc6, 0x74, 0xcf, 0xfb,
        ],
        len: nist_msg.len() as u32,
        msg,
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::TEST_ONLY_HMAC384_VERIFY),
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
