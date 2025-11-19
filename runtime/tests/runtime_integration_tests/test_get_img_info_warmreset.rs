use crate::common::{run_rt_test, wait_runtime_ready, RuntimeTestArgs};

use crate::test_set_auth_manifest::{
    create_auth_manifest, create_auth_manifest_with_metadata, AuthManifestBuilderCfg,
};

use caliptra_auth_man_types::{
    Addr64, AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
};

use caliptra_builder::ImageOptions;

use caliptra_common::mailbox_api::{
    CommandId, GetImageInfoReq, GetImageInfoResp, ImageHashSource, MailboxReq, MailboxReqHeader,
    SetAuthManifestReq,
};

use caliptra_hw_model::{DefaultHwModel, HwModel};

use caliptra_image_types::FwVerificationPqcKeyType;

use zerocopy::{FromBytes, IntoBytes};

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

fn set_auth_manifest(auth_manifest: Option<AuthorizationManifest>) -> DefaultHwModel {
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    wait_runtime_ready(&mut model);

    let auth_manifest = if let Some(auth_manifest) = auth_manifest {
        auth_manifest
    } else {
        create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        })
    };

    let buf = auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    model
}

#[test]
#[cfg(not(any(feature = "fpga_realtime", feature = "fpga_subsystem")))]
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
    model.warm_reset();
    wait_runtime_ready(&mut model);

    // --- AFTER warm reset ---
    let resp_after = get_image_info(&mut model, FW_ID_1);

    // The image info for the same fw_id should be stable across warm reset.

    assert_eq!(
        resp_before, resp_after,
        "GET_IMAGE_INFO  changed across warm reset"
    );
}
