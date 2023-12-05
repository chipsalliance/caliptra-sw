// Licensed under the Apache-2.0 license

use crate::common::{assert_error, execute_dpe_cmd, run_rt_test, DpeResult};
use caliptra_common::mailbox_api::{
    CommandId, GetTaggedTciReq, GetTaggedTciResp, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_hw_model::HwModel;
use dpe::{
    commands::{Command, DeriveChildCmd, DeriveChildFlags, DestroyCtxCmd},
    context::ContextHandle,
    response::Response,
    DPE_PROFILE,
};
use zerocopy::FromBytes;

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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_CONTEXT_ALREADY_TAGGED,
        resp,
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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_DUPLICATE_TAG,
        resp,
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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE,
        resp,
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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE,
        resp,
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
    let destroy_ctx_cmd = DestroyCtxCmd {
        handle: ContextHandle::default(),
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DestroyCtx(destroy_ctx_cmd),
        DpeResult::Success,
    );
    let Some(Response::DestroyCtx(_)) = resp else {
        panic!("Wrong response type!");
    };

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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE,
        resp,
    );
}

#[test]
fn test_tagging_retired_context() {
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

    // retire tagged context via DeriveChild
    let derive_child_cmd = DeriveChildCmd {
        handle: ContextHandle::default(),
        data: [0u8; DPE_PROFILE.get_hash_size()],
        flags: DeriveChildFlags::MAKE_DEFAULT,
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveChild(derive_child_cmd),
        DpeResult::Success,
    );
    let Some(Response::DeriveChild(_)) = resp else {
        panic!("Wrong response type!");
    };

    // check that we cannot get tagged tci for a retired context
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
    assert_error(
        &mut model,
        caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE,
        resp,
    );
}
