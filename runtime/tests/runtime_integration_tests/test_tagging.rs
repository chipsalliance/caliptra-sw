// Licensed under the Apache-2.0 license

use crate::common::run_rt_test;
use caliptra_common::mailbox_api::{
    CommandId, GetTaggedTciReq, GetTaggedTciResp, InvokeDpeReq, MailboxReq, MailboxReqHeader,
    TagTciReq,
};
use caliptra_hw_model::{HwModel, ModelError};
use dpe::{
    commands::{Command, CommandHdr, DestroyCtxCmd},
    context::ContextHandle,
};
use zerocopy::{AsBytes, FromBytes};

const TAG: u32 = 1;
const INVALID_TAG: u32 = 2;
const DEFAULT_HANDLE: [u8; 16] = [0u8; 16];
const BAD_HANDLE: [u8; 16] = [1u8; 16];

#[test]
fn test_tagging_default_context() {
    let mut model = run_rt_test(None, None, None);

    // Tag default context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // get tcis of default context
    let mut cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We expected a response");
    let _ = GetTaggedTciResp::read_from(resp.as_slice()).unwrap();
}

#[test]
fn test_tagging_a_tagged_context() {
    let mut model = run_rt_test(None, None, None);

    // Tag default context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // Check that tagging a tagged context fails
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: INVALID_TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_CONTEXT_ALREADY_TAGGED)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_CONTEXT_ALREADY_TAGGED)
    );
}

#[test]
fn test_duplicate_tag() {
    let mut model = run_rt_test(None, None, None);

    // Tag default context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // Check that adding a duplicate tag fails
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_DUPLICATE_TAG)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_DUPLICATE_TAG)
    );
}

#[test]
fn test_get_tagged_tci_on_non_existent_tag() {
    let mut model = run_rt_test(None, None, None);

    // Check that DPE_GET_TAGGED_TCI fails if the tag does not exist
    let mut cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: INVALID_TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
    );
}

#[test]
fn test_tagging_inactive_context() {
    let mut model = run_rt_test(None, None, None);

    // check that we cannot tag an inactive context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: BAD_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
    );
}

#[test]
fn test_tagging_destroyed_context() {
    let mut model = run_rt_test(None, None, None);

    // Tag default context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // destroy tagged context
    let mut data = [0u8; InvokeDpeReq::DATA_MAX_SIZE];
    let destroy_ctx_cmd = DestroyCtxCmd {
        handle: ContextHandle::default(),
    };
    let cmd_hdr = CommandHdr::new_for_test(Command::DESTROY_CONTEXT);
    let cmd_hdr_buf = cmd_hdr.as_bytes();
    data[..cmd_hdr_buf.len()].copy_from_slice(cmd_hdr_buf);
    let dpe_cmd_buf = destroy_ctx_cmd.as_bytes();
    data[cmd_hdr_buf.len()..cmd_hdr_buf.len() + dpe_cmd_buf.len()].copy_from_slice(dpe_cmd_buf);
    let mut cmd = MailboxReq::InvokeDpeCommand(InvokeDpeReq {
        hdr: MailboxReqHeader { chksum: 0 },
        data,
        data_size: (cmd_hdr_buf.len() + dpe_cmd_buf.len()) as u32,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::INVOKE_DPE), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We should have received a response");

    // check that we cannot get tagged tci for a destroyed context
    let mut cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            cmd.as_bytes().unwrap(),
        )
        .unwrap_err();
    if let ModelError::MailboxCmdFailed(code) = resp {
        assert_eq!(
            code,
            u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
        );
    }
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE)
    );
}
