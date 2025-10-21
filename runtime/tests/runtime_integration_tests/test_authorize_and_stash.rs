// Licensed under the Apache-2.0 license

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::{
    create_auth_manifest, create_auth_manifest_with_metadata, AuthManifestBuilderCfg,
};
use crate::test_update_reset::update_fw;
use caliptra_api::mailbox::{MailboxRespHeader, VerifyAuthManifestReq};
use caliptra_api::SocManager;
use caliptra_auth_man_types::{
    Addr64, AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_builder::firmware::APP_WITH_UART;
use caliptra_builder::{
    firmware::{self, FMC_WITH_UART},
    ImageOptions,
};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader, SetAuthManifestReq,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::RtBootStatus;
use caliptra_runtime::{IMAGE_AUTHORIZED, IMAGE_HASH_MISMATCH, IMAGE_NOT_AUTHORIZED};
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

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
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = if let Some(auth_manifest) = auth_manifest {
        auth_manifest
    } else {
        create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            svn: 1,
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

pub fn set_auth_manifest_with_test_sram(
    auth_manifest: Option<AuthorizationManifest>,
    test_sram: &[u8],
) -> DefaultHwModel {
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        test_sram: Some(test_sram),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = if let Some(auth_manifest) = auth_manifest {
        auth_manifest
    } else {
        create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            svn: 1,
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
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        image_options,
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
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    let updated_fw_image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &firmware::runtime_tests::MBOX,
        image_options,
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
        ..Default::default()
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
        ..Default::default()
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
            ..Default::default()
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

#[test]
fn test_authorize_and_stash_after_update_reset() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 0,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
        ..Default::default()
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

    // Trigger an update reset.
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    update_fw(&mut model, &APP_WITH_UART, image_options);

    // Re-authorize the image.
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
fn test_authorize_and_stash_after_update_reset_unauthorized_fw_id() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_127: [u8; 4] = [0x7F, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 0,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
        ..Default::default()
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );

    // Trigger an update reset.
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    update_fw(&mut model, &APP_WITH_UART, image_options);

    // Attempt Authorization with a unauthorized fw id.
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );
}

#[test]
fn test_authorize_and_stash_after_update_reset_bad_hash() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 0,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_0,
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

    // Trigger an update reset.
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    update_fw(&mut model, &APP_WITH_UART, image_options);

    // Attempt Authorization with a bad image hash.
    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_0,
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
fn test_authorize_and_stash_after_update_reset_skip_auth() {
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

    // Trigger an update reset.
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    update_fw(&mut model, &APP_WITH_UART, image_options);

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
fn test_authorize_and_stash_after_update_reset_multiple_set_manifest() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);

    const FW_ID_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    const FW_ID_127: [u8; 4] = [0x7F, 0x00, 0x00, 0x00];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 0,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest(Some(auth_manifest));

    // Valid authorization.
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

    // Invalid authorization.
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );

    // Trigger an update reset.
    let image_options = ImageOptions {
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    };
    update_fw(&mut model, &APP_WITH_UART, image_options);

    //
    // Check again
    //

    // Valid authorization.
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

    // Invalid authorization.
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );

    //
    // Set another manifest.
    //
    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: 127,
        flags: flags.0,
        digest: IMAGE_DIGEST1,
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);

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

    // Valid authorization.
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

    // Invalid authorization.
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );
}

#[test]
fn test_authorize_from_load_address() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let mut hasher = Sha384::new();
    hasher.update(load_memory_contents);
    let fw_digest = hasher.finalize();

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: fw_digest.into(),
        image_load_address: Addr64 {
            lo: 0x0050_0000,
            hi: 0x0000_0000,
        },
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: [0; 48],
        source: ImageHashSource::LoadAddress as u32,
        flags: 0, // Don't skip stash
        image_size: load_memory_contents.len() as u32,
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
fn test_authorize_from_load_address_incorrect_digest() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: [0; 48],
        image_load_address: Addr64 {
            lo: 0x0050_0000,
            hi: 0x0000_0000,
        },
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: [0; 48],
        source: ImageHashSource::LoadAddress as u32,
        flags: 0, // Don't skip stash
        image_size: load_memory_contents.len() as u32,
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
fn test_authorize_from_staging_address() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::StagingAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let mut hasher = Sha384::new();
    hasher.update(load_memory_contents);
    let fw_digest = hasher.finalize();

    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: fw_digest.into(),
        image_staging_address: Addr64 {
            lo: 0x0050_0000,
            hi: 0x0000_0000,
        },
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: [0; 48],
        source: ImageHashSource::StagingAddress as u32,
        flags: 0, // Don't skip stash
        image_size: load_memory_contents.len() as u32,
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
fn test_authorize_from_staging_address_incorrect_digest() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::StagingAddress as u32);

    let load_memory_contents = [0x55u8; 512];
    let image_metadata = vec![AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: [0; 48],
        image_staging_address: Addr64 {
            lo: 0x0050_0000,
            hi: 0x0000_0000,
        },
        ..Default::default()
    }];
    let auth_manifest = create_auth_manifest_with_metadata(image_metadata);
    let mut model = set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents);

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: [0; 48],
        source: ImageHashSource::StagingAddress as u32,
        flags: 0, // Don't skip stash
        image_size: load_memory_contents.len() as u32,
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
fn test_verify_valid_manifest() {
    // Create the model
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Create a valid auth manifest
    let valid_auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        svn: 1,
    });

    // Verify the manifest
    let buf = valid_auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut verify_auth_manifest_cmd = MailboxReq::VerifyAuthManifest(VerifyAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    verify_auth_manifest_cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::VERIFY_AUTH_MANIFEST),
        verify_auth_manifest_cmd.as_bytes().unwrap(),
    );

    match result {
        Ok(Some(resp)) => {
            let verify_auth_manifest_resp =
                MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
            assert_eq!(
                verify_auth_manifest_resp.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED
            );
        }
        Ok(None) => panic!("Expected a response but got None"),
        Err(e) => panic!("Mailbox execution failed: {:?}", e),
    }

    // Verify that sending a VERIFY_MANIFEST command doesn't set the manifest
    // Authorizing an image should fail
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
    assert_eq!(
        authorize_and_stash_resp.auth_req_result,
        IMAGE_NOT_AUTHORIZED
    );

    // Set the manifest
    let buf = valid_auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::SET_AUTH_MANIFEST),
        set_auth_manifest_cmd.as_bytes().unwrap(),
    );

    match result {
        Ok(Some(resp)) => {
            let set_auth_manifest_resp =
                MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
            assert_eq!(
                set_auth_manifest_resp.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED
            );
        }
        Ok(None) => panic!("Expected a response but got None"),
        Err(e) => panic!("Mailbox execution failed: {:?}", e),
    }

    // Now authorizing an image should succeed
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
fn test_verify_invalid_manifest() {
    // Create the model
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    // Create an invalid auth manifest
    let valid_auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
    });

    // Set the valid manifest first
    let buf = valid_auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::SET_AUTH_MANIFEST),
        set_auth_manifest_cmd.as_bytes().unwrap(),
    );

    match result {
        Ok(Some(resp)) => {
            let set_auth_manifest_resp =
                MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
            assert_eq!(
                set_auth_manifest_resp.fips_status,
                MailboxRespHeader::FIPS_STATUS_APPROVED
            );
        }
        Ok(None) => panic!("Expected a response but got None"),
        Err(e) => panic!("Mailbox execution failed: {:?}", e),
    }

    // Modify the manifest to make it invalid (e.g., change a byte)
    let mut invalid_auth_manifest = valid_auth_manifest;
    invalid_auth_manifest.as_mut_bytes()[0] ^= 0xFF;

    // Verify the invalid manifest
    let buf = invalid_auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut verify_auth_manifest_cmd = MailboxReq::VerifyAuthManifest(VerifyAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    verify_auth_manifest_cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::VERIFY_AUTH_MANIFEST),
        verify_auth_manifest_cmd.as_bytes().unwrap(),
    );

    match result {
        Ok(Some(resp)) => panic!(
            "Expected an error response but got a valid response: {:?}",
            resp
        ),
        Ok(None) => panic!("Expected a response but got None"),
        Err(_) => {
            // Expected error due to invalid manifest
        }
    }

    // Authorize and stash an image with the old manifest (i.e. the valid one)
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
}

// #[test]
// fn test_verify_valid_manifest_warm_reset() {
//     // Create the model
//     let runtime_args = RuntimeTestArgs {
//         test_image_options: Some(ImageOptions {
//             pqc_key_type: FwVerificationPqcKeyType::LMS,
//             ..Default::default()
//         }),
//         ..Default::default()
//     };

//     let mut model = run_rt_test(runtime_args);

//     model.step_until(|m| {
//         m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
//     });

//     // Create a valid auth manifest
//     let valid_auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
//         manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
//         pqc_key_type: FwVerificationPqcKeyType::LMS,
//         svn: 1,
//     });

//     // Verify the manifest
//     let buf = valid_auth_manifest.as_bytes();
//     let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
//     auth_manifest_slice[..buf.len()].copy_from_slice(buf);

//     let mut verify_auth_manifest_cmd = MailboxReq::VerifyAuthManifest(VerifyAuthManifestReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         manifest_size: buf.len() as u32,
//         manifest: auth_manifest_slice,
//     });
//     verify_auth_manifest_cmd.populate_chksum().unwrap();

//     let result = model.mailbox_execute(
//         u32::from(CommandId::VERIFY_AUTH_MANIFEST),
//         verify_auth_manifest_cmd.as_bytes().unwrap(),
//     );

//     match result {
//         Ok(Some(resp)) => {
//             let verify_auth_manifest_resp =
//                 MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
//             assert_eq!(
//                 verify_auth_manifest_resp.fips_status,
//                 MailboxRespHeader::FIPS_STATUS_APPROVED
//             );
//         }
//         Ok(None) => panic!("Expected a response but got None"),
//         Err(e) => panic!("Mailbox execution failed: {:?}", e),
//     }

//     // Verify that sending a VERIFY_MANIFEST command doesn't set the manifest
//     // Authorizing an image should fail
//     let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         fw_id: FW_ID_1,
//         measurement: IMAGE_DIGEST1,
//         source: ImageHashSource::InRequest as u32,
//         flags: 0, // Don't skip stash
//         ..Default::default()
//     });
//     authorize_and_stash_cmd.populate_chksum().unwrap();

//     let resp = model
//         .mailbox_execute(
//             u32::from(CommandId::AUTHORIZE_AND_STASH),
//             authorize_and_stash_cmd.as_bytes().unwrap(),
//         )
//         .unwrap()
//         .expect("We should have received a response");

//     let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
//     assert_eq!(
//         authorize_and_stash_resp.auth_req_result,
//         IMAGE_NOT_AUTHORIZED
//     );

//     // Set the manifest
//     let buf = valid_auth_manifest.as_bytes();
//     let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
//     auth_manifest_slice[..buf.len()].copy_from_slice(buf);

//     let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         manifest_size: buf.len() as u32,
//         manifest: auth_manifest_slice,
//     });
//     set_auth_manifest_cmd.populate_chksum().unwrap();

//     let result = model.mailbox_execute(
//         u32::from(CommandId::SET_AUTH_MANIFEST),
//         set_auth_manifest_cmd.as_bytes().unwrap(),
//     );

//     match result {
//         Ok(Some(resp)) => {
//             let set_auth_manifest_resp =
//                 MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
//             assert_eq!(
//                 set_auth_manifest_resp.fips_status,
//                 MailboxRespHeader::FIPS_STATUS_APPROVED
//             );
//         }
//         Ok(None) => panic!("Expected a response but got None"),
//         Err(e) => panic!("Mailbox execution failed: {:?}", e),
//     }

//     // Now authorizing an image should succeed
//     let resp = model
//         .mailbox_execute(
//             u32::from(CommandId::AUTHORIZE_AND_STASH),
//             authorize_and_stash_cmd.as_bytes().unwrap(),
//         )
//         .unwrap()
//         .expect("We should have received a response");

//     let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
//     assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);

//     // Perform warm reset
//     model.warm_reset_flow(&Fuses::default());

//     model.step_until(|m| {
//         m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
//     });

//     // Create a valid auth manifest
//     let valid_auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
//         manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
//         pqc_key_type: FwVerificationPqcKeyType::LMS,
//         svn: 1,
//     });

//     // Verify the manifest
//     let buf = valid_auth_manifest.as_bytes();
//     let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
//     auth_manifest_slice[..buf.len()].copy_from_slice(buf);

//     let mut verify_auth_manifest_cmd = MailboxReq::VerifyAuthManifest(VerifyAuthManifestReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         manifest_size: buf.len() as u32,
//         manifest: auth_manifest_slice,
//     });
//     verify_auth_manifest_cmd.populate_chksum().unwrap();

//     let result = model.mailbox_execute(
//         u32::from(CommandId::VERIFY_AUTH_MANIFEST),
//         verify_auth_manifest_cmd.as_bytes().unwrap(),
//     );

//     match result {
//         Ok(Some(resp)) => {
//             let verify_auth_manifest_resp =
//                 MailboxRespHeader::read_from_bytes(resp.as_slice()).unwrap();
//             assert_eq!(
//                 verify_auth_manifest_resp.fips_status,
//                 MailboxRespHeader::FIPS_STATUS_APPROVED
//             );
//         }
//         Ok(None) => panic!("Expected a response but got None"),
//         Err(e) => panic!("Mailbox execution failed: {:?}", e),
//     }
// }

// #[test]
// fn test_authorize_and_stash_cmd_success_warm_reset() {
//     let mut model = set_auth_manifest(None);

//     let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         fw_id: FW_ID_1,
//         measurement: IMAGE_DIGEST1,
//         source: ImageHashSource::InRequest as u32,
//         flags: 0, // Don't skip stash
//         ..Default::default()
//     });
//     authorize_and_stash_cmd.populate_chksum().unwrap();

//     let resp = model
//         .mailbox_execute(
//             u32::from(CommandId::AUTHORIZE_AND_STASH),
//             authorize_and_stash_cmd.as_bytes().unwrap(),
//         )
//         .unwrap()
//         .expect("We should have received a response");

//     let authorize_and_stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
//     assert_eq!(authorize_and_stash_resp.auth_req_result, IMAGE_AUTHORIZED);

//     // create a new fw image with the runtime replaced by the mbox responder
//     let image_options = ImageOptions {
//         pqc_key_type: FwVerificationPqcKeyType::LMS,
//         ..Default::default()
//     };
//     let updated_fw_image = caliptra_builder::build_and_sign_image(
//         &FMC_WITH_UART,
//         &firmware::runtime_tests::MBOX,
//         image_options,
//     )
//     .unwrap()
//     .to_bytes()
//     .unwrap();

//     // trigger an update reset so we can use commands in mbox responder
//     model
//         .mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &updated_fw_image)
//         .unwrap();

//     let rt_journey_pcr_resp = model.mailbox_execute(0x1000_0000, &[]).unwrap().unwrap();
//     let rt_journey_pcr: [u8; 48] = rt_journey_pcr_resp.as_bytes().try_into().unwrap();

//     let valid_pauser_hash_resp = model.mailbox_execute(0x2000_0000, &[]).unwrap().unwrap();
//     let valid_pauser_hash: [u8; 48] = valid_pauser_hash_resp.as_bytes().try_into().unwrap();

//     // hash expected DPE measurements in order to check that stashed measurement was added to DPE
//     let mut hasher = Sha384::new();
//     hasher.update(rt_journey_pcr);
//     hasher.update(valid_pauser_hash);
//     hasher.update(IMAGE_DIGEST1);
//     let expected_measurement_hash = hasher.finalize();

//     let dpe_measurement_hash = model.mailbox_execute(0x3000_0000, &[]).unwrap().unwrap();
//     assert_eq!(expected_measurement_hash.as_bytes(), dpe_measurement_hash);

//     // Perform warm reset
//     model.warm_reset_flow(&Fuses::default());

//     model.step_until(|m| {
//         m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
//     });

//     let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
//         hdr: MailboxReqHeader { chksum: 0 },
//         fw_id: FW_ID_2,
//         measurement: IMAGE_DIGEST_BAD,
//         source: ImageHashSource::InRequest as u32,
//         flags: 0, // Don't skip stash
//         ..Default::default()
//     });
//     authorize_and_stash_cmd.populate_chksum().unwrap();

//     let resp = model
//         .mailbox_execute(
//             u32::from(CommandId::AUTHORIZE_AND_STASH),
//             authorize_and_stash_cmd.as_bytes().unwrap(),
//         )
//         .unwrap()
//         .expect("We should have received a response");
// }
