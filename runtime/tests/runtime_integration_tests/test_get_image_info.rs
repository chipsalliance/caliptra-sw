// Licensed under the Apache-2.0 license

use crate::test_authorize_and_stash::set_auth_manifest;
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_api::mailbox::{GetImageInfoReq, GetImageInfoResp};
use caliptra_auth_man_types::{Addr64, AuthManifestImageMetadata, ImageMetadataFlags};
use caliptra_common::mailbox_api::{CommandId, ImageHashSource, MailboxReq, MailboxReqHeader};
use caliptra_hw_model::HwModel;
use zerocopy::FromBytes;

pub const FW_ID_1: u32 = 1;
pub const FW_ID_2: u32 = 2;
pub const FW_ID_BAD: u32 = 3;

#[test]
fn test_get_image_info_success() {
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

    let mut get_image_info_cmd = MailboxReq::GetImageInfo(GetImageInfoReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1.to_le_bytes(),
    });

    get_image_info_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IMAGE_INFO),
            get_image_info_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let get_image_info_resp = GetImageInfoResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(get_image_info_resp.flags, flags1.0);
    assert_eq!(get_image_info_resp.image_staging_address_high, 0u32);
    assert_eq!(get_image_info_resp.image_staging_address_low, 0x0050_0000);
    assert_eq!(get_image_info_resp.image_load_address_high, 0u32);
    assert_eq!(get_image_info_resp.image_load_address_low, 0u32);
}

#[test]
fn test_get_image_info_2() {
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
            image_load_address: Addr64 {
                lo: 0x0050_0000,
                hi: 0x0000_0000,
            },
            ..Default::default()
        },
    ];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    let mut get_image_info_cmd = MailboxReq::GetImageInfo(GetImageInfoReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2.to_le_bytes(),
    });

    get_image_info_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::GET_IMAGE_INFO),
            get_image_info_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let get_image_info_resp = GetImageInfoResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(get_image_info_resp.flags, flags2.0);
    assert_eq!(get_image_info_resp.image_staging_address_high, 0u32);
    assert_eq!(get_image_info_resp.image_staging_address_low, 0u32);
    assert_eq!(get_image_info_resp.image_load_address_high, 0u32);
    assert_eq!(get_image_info_resp.image_load_address_low, 0x0050_0000);
}

#[test]
fn test_get_image_info_non_existent() {
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
            image_load_address: Addr64 {
                lo: 0x0050_0000,
                hi: 0x0000_0000,
            },
            ..Default::default()
        },
    ];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    let mut get_image_info_cmd = MailboxReq::GetImageInfo(GetImageInfoReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_BAD.to_le_bytes(),
    });

    get_image_info_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(
        u32::from(CommandId::GET_IMAGE_INFO),
        get_image_info_cmd.as_bytes().unwrap(),
    );

    assert!(resp.is_err());
}
