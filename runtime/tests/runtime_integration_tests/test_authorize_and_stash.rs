// Licensed under the Apache-2.0 license

use crate::common::run_rt_test;
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader,
};
use caliptra_hw_model::HwModel;
use caliptra_runtime::RtBootStatus;
use caliptra_runtime::DENY_IMAGE_AUTHORIZATION;
use zerocopy::FromBytes;

#[test]
fn test_authorize_and_stash_cmd_deny_authorization() {
    let mut model = run_rt_test(None, None, None);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let image_digest1: [u8; 48] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        measurement: image_digest1,
        source: ImageHashSource::InRequest as u32,
        flags: 0,
        ..Default::default()
    });
    authorize_and_stash_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            authorize_and_stash_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from(resp.as_slice()).unwrap();
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        DENY_IMAGE_AUTHORIZATION
    );
}
