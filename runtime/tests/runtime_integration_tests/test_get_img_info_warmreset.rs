use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;

use crate::test_authorize_and_stash::set_auth_manifest;

use caliptra_auth_man_types::{Addr64, AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_common::mailbox_api::{
    CommandId, GetImageInfoReq, GetImageInfoResp, ImageHashSource, MailboxReq, MailboxReqHeader,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use zerocopy::FromBytes;

const FW_ID_1: u32 = 1;
const FW_ID_2: u32 = 2;

/// Helper: issue GET_IMAGE_INFO for a given fw_id and return a *owned* response.
fn get_image_info(model: &mut DefaultHwModel, fw_id: u32) -> GetImageInfoResp {
    let mut get_image_info_cmd = MailboxReq::GetImageInfo(GetImageInfoReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: fw_id.to_le_bytes(),
    });

    get_image_info_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IMAGE_INFO),
            get_image_info_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("GET_IMAGE_INFO should return a response");

    // Use read_from_bytes to get an owned struct (easier to compare later).
    GetImageInfoResp::read_from_bytes(resp.as_slice()).expect("failed to parse GetImageInfoResp")
}

#[test]
fn test_get_image_info_persists_after_warm_reset() {
    //  manifest setup
    let mut flags1 = ImageMetadataFlags(0);
    flags1.set_ignore_auth_check(false);
    flags1.set_image_source(ImageHashSource::StagingAddress as u32);

    let mut flags2 = ImageMetadataFlags(0);
    flags2.set_ignore_auth_check(true);
    flags2.set_image_source(ImageHashSource::LoadAddress as u32);

    let image_metadata = vec![
        AuthManifestImageMetadata {
            fw_id: FW_ID_1,
            flags: flags1.0,
            image_staging_address: Addr64 {
                lo: 0x0050_0000,
                hi: 0x0000_0000,
            },
            ..Default::default()
        },
        AuthManifestImageMetadata {
            fw_id: FW_ID_2,
            flags: flags2.0,
            image_staging_address: Addr64 {
                lo: 0x0050_0000,
                hi: 0x0000_0000,
            },
            ..Default::default()
        },
    ];

    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    // --- BEFORE warm reset ---
    let resp_before = get_image_info(&mut model, FW_ID_1);

    assert_eq!(resp_before.flags, flags1.0);
    assert_eq!(resp_before.image_staging_address_high, 0u32);
    assert_eq!(resp_before.image_staging_address_low, 0x0050_0000);
    assert_eq!(resp_before.image_load_address_high, 0u32);
    assert_eq!(resp_before.image_load_address_low, 0u32);

    // --- Warm reset ---
    model.warm_reset_flow().unwrap();

    // --- AFTER warm reset ---
    let resp_after = get_image_info(&mut model, FW_ID_1);

    // The image info for the same fw_id should be stable across warm reset.

    assert_eq!(
        resp_before, resp_after,
        "GET_IMAGE_INFO  changed across warm reset"
    );
}
