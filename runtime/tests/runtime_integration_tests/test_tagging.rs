// Licensed under the Apache-2.0 license

use crate::common::{assert_error, execute_dpe_cmd, run_rt_test, DpeResult, RuntimeTestArgs};
use caliptra_common::mailbox_api::{
    CommandId, GetTaggedTciReq, GetTaggedTciResp, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_hw_model::HwModel;
use dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags, DestroyCtxCmd},
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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let _ = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();
}

#[test]
fn test_tagging_a_tagged_context() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
    let mut model = run_rt_test(RuntimeTestArgs::default());

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
        &mut Command::DestroyCtx(&destroy_ctx_cmd),
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
    let mut model = run_rt_test(RuntimeTestArgs::default());

    // retire context via DeriveContext
    let derive_context_cmd = DeriveContextCmd {
        handle: ContextHandle::default(),
        data: [0u8; DPE_PROFILE.get_hash_size()],
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::Success,
    );
    let Some(Response::DeriveContext(derive_context_resp)) = resp else {
        panic!("Wrong response type!");
    };
    let new_handle = derive_context_resp.handle;

    // check that we cannot tag retired context
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
        caliptra_drivers::CaliptraError::RUNTIME_TAGGING_FAILURE,
        resp,
    );

    // tag new context
    let mut cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: new_handle.0,
        tag: TAG,
    });
    cmd.populate_chksum().unwrap();
    let _ = model
        .mailbox_execute(u32::from(CommandId::DPE_TAG_TCI), cmd.as_bytes().unwrap())
        .unwrap()
        .expect("We expected a response");

    // retire tagged context via derive child
    let derive_context_cmd = DeriveContextCmd {
        handle: new_handle,
        data: [0u8; DPE_PROFILE.get_hash_size()],
        flags: DeriveContextFlags::empty(),
        tci_type: 0,
        target_locality: 0,
    };
    let resp = execute_dpe_cmd(
        &mut model,
        &mut Command::DeriveContext(&derive_context_cmd),
        DpeResult::Success,
    );
    let Some(Response::DeriveContext(_)) = resp else {
        panic!("Wrong response type!");
    };

    // check that we can get tagged tci for a retired context
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
    let _ = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();
}
