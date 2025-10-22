use crate::common::{build_ready_runtime_model, wait_runtime_ready, BuildArgs};

use caliptra_common::mailbox_api::{
    CommandId, GetTaggedTciReq, GetTaggedTciResp, MailboxReq, MailboxReqHeader, TagTciReq,
};
use caliptra_hw_model::{DeviceLifecycle, HwModel, SecurityState};
use zerocopy::FromBytes;

const TAG: u32 = 1;
const DEFAULT_HANDLE: [u8; 16] = [0u8; 16];

#[test]
fn test_dpe_tag_tci_after_warm_reset() {
    // --- Boot time ---
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, _, _, _) = build_ready_runtime_model(args);

    // Tag default context
    let mut tag_cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: DEFAULT_HANDLE,
        tag: TAG,
    });
    tag_cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::DPE_TAG_TCI),
            tag_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Expected TagTci response before warm reset");

    // Read back the tagged TCI
    let mut get_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: TAG,
    });
    get_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Expected GetTaggedTci response before warm reset");

    let tci_resp_before = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();
    assert!(
        tci_resp_before.tci_current.iter().any(|&b| b != 0),
        "current_tci looks all-zero before reset"
    );

    // ---- Warm reset & wait ready----
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // Read back the tagged TCI again
    let mut get_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: TAG,
    });
    get_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Expected GetTaggedTci response after warm reset");

    let tci_resp_after = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();
    assert!(
        tci_resp_after.tci_current.iter().any(|&b| b != 0),
        "current_tci looks all-zero after reset"
    );

    assert_eq!(
        tci_resp_before, tci_resp_after,
        "STASH_MEASUREMENT response changed across warm reset"
    );
}
