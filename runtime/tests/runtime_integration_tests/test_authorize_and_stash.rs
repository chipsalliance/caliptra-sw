// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::{create_auth_manifest, create_auth_manifest_with_metadata};
use caliptra_api::SocManager;
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_builder::{
    firmware::{self, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader, SetAuthManifestReq,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;
use caliptra_runtime::{IMAGE_AUTHORIZED, IMAGE_NOT_AUTHORIZED};
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

const IMAGE_HASH_MISMATCH: u32 = 0x8BFB95CB; // FW ID matched, but image digest mismatched.

pub const IMAGE_DIGEST1: [u8; 48] = [
    0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];

pub const IMAGE_DIGEST_BAD: [u8; 48] = [
    0x39, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];

pub const FW_ID_1: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
pub const FW_ID_2: [u8; 4] = [0x02, 0x00, 0x00, 0x00];
pub const FW_ID_BAD: [u8; 4] = [0xDE, 0xED, 0xBE, 0xEF];

fn set_auth_manifest(auth_manifest: Option<AuthorizationManifest>) -> DefaultHwModel {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = if let Some(auth_manifest) = auth_manifest {
        auth_manifest
    } else {
        create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED)
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
fn test_authorize_and_stash_cmd_deny_authorization() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
        fw_id: FW_ID_BAD,
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::ref_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );

    // create a new fw image with the runtime replaced by the mbox responder
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // We don't expect the image_digest to be part of the stash
    let mut hasher = Sha384::new();
    hasher.update(rt_journey_pcr);
    hasher.update(valid_pauser_hash);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}

#[test]
fn test_authorize_and_stash_cmd_success() {
    let mut model = set_auth_manifest(None);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);

    // create a new fw image with the runtime replaced by the mbox responder
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
        .unwrap();

    let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
    let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

    let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
    let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

    // hash expected DPE measurements in order to check that stashed measurement was added to DPE
    let mut hasher = Sha384::new();
    hasher.update(rt_journey_pcr);
    hasher.update(valid_pauser_hash);
    hasher.update(IMAGE_DIGEST1);
    let expected_measurement_hash = hasher.finalize();

    let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
    assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);
}

#[test]
fn test_authorize_and_stash_cmd_deny_authorization_no_hash_or_id() {
    let mut model = set_auth_manifest(None);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );
}

#[test]
fn test_authorize_and_stash_cmd_deny_authorization_wrong_id_no_hash() {
    let mut model = set_auth_manifest(None);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_BAD,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );
}

#[test]
fn test_authorize_and_stash_cmd_deny_authorization_wrong_hash() {
    let mut model = set_auth_manifest(None);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: IMAGE_DIGEST_BAD,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_HASH_MISMATCH
    );
}

#[test]
fn test_authorize_and_stash_cmd_success_skip_auth() {
    let mut model = set_auth_manifest(None);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2,
        measurement: IMAGE_DIGEST_BAD,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);
}

#[test]
fn test_authorize_and_stash_fwid_0() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 0,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_0,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);
}

#[test]
fn test_authorize_and_stash_fwid_127() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_127: [u8; 4] = [0x7F, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 127,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_127,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Don't skip stash
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

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);
}

#[test]
fn test_authorize_and_stash_cmd_deny_second_bad_hash() {
    {
        let mut model = set_auth_manifest(None);

        let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: FW_ID_1,
            measurement: IMAGE_DIGEST1,
            source: ImageHashSource::InRequest as u32,
            flags: 0, // Don't skip stash
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

        let authorize_and_stash_resp =
            AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
        assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);
    }

    {
        let mut flags = ImageMetadataFlags(0);
        flags.set_ignore_auth_check(false);
        flags.set_image_source(ImageHashSource::InRequest as u32);

        let image_metadata = vec![AuthManifestImageMetadata {
            fw_id: 1,
            flags: flags.0,
            digest: IMAGE_DIGEST_BAD,
        }];
        let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
        let mut model = set_auth_manifest(Some(auth_manifest));

        let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
            hdr: MailboxReqHeader { chksum: 0 },
            fw_id: FW_ID_1,
            measurement: IMAGE_DIGEST1,
            source: ImageHashSource::InRequest as u32,
            flags: 0, // Don't skip stash
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

        let authorize_and_stash_resp =
            AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
        assert_eq!(
            authorize_and_stash_resp.auth_req_result,
            IMAGE_HASH_MISMATCH
        );
    }
}
