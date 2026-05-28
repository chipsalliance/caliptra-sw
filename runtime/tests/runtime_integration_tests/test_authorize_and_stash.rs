// Licensed under the Apache-2.0 license

use crate::common::{calculate_cptra_config_init_vals_hash, run_rt_test, RuntimeTestArgs};
use crate::test_set_auth_manifest::{
    create_auth_manifest, create_auth_manifest_with_metadata, AuthManifestBuilderCfg,
};
use crate::test_update_reset::update_fw;
use caliptra_api::mailbox::{AuthAndStashFlags, MailboxRespHeader, VerifyAuthManifestReq};
use caliptra_auth_man_types::{
    Addr64, AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
};
use caliptra_builder::firmware::APP_WITH_UART;
use caliptra_builder::{firmware::FMC_WITH_UART, ImageOptions};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, GetTaggedTciReq, GetTaggedTciResp,
    ImageHashSource, MailboxReq, MailboxReqHeader, SetAuthManifestReq, TagTciReq,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_image_types::FwVerificationPqcKeyType;
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

pub const IMAGE_DIGEST2: [u8; 48] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
];

#[cfg(feature = "fpga_subsystem")]
pub const TEST_SRAM_SIZE: usize = 0x1000;
#[cfg(feature = "fpga_subsystem")]
const MCI_BASE: u32 = 0xA8000000;
#[cfg(feature = "fpga_subsystem")]
const MCU_MBOX_SRAM_BASE: u32 = MCI_BASE + 0x400000;
#[cfg(feature = "fpga_subsystem")]
pub const TEST_SRAM_BASE: Addr64 = Addr64 {
    lo: MCU_MBOX_SRAM_BASE,
    hi: 0x0000_0000,
};

#[cfg(not(feature = "fpga_subsystem"))]
pub const TEST_SRAM_BASE: Addr64 = Addr64 {
    lo: 0x0050_0000,
    hi: 0x0000_0000,
};

fn set_auth_manifest(auth_manifest: Option<AuthorizationManifest>) -> DefaultHwModel {
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);
    model.step_until_ready_for_runtime();

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
    mcu_image: &[u8],
) -> DefaultHwModel {
    let runtime_args = RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        test_sram: Some(test_sram),
        soc_manifest: Some(
            auth_manifest
                .as_ref()
                .map(|m| m.as_bytes())
                .unwrap_or_default(),
        ),
        mcu_fw_image: Some(mcu_image),
        ..Default::default()
    };

    let mut model = run_rt_test(runtime_args);

    model.step_until_ready_for_runtime();

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

    model.step_until_ready_for_runtime();

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
        crate::test_update_reset::mbox_test_image(),
        image_options,
    )
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &updated_fw_image.to_bytes().unwrap(),
        )
        .unwrap();

    let rt_current_pcr_resp = model.mailbox_execute(0x1000_0001, &[]).unwrap().unwrap();
    let rt_current_pcr: [u8; 48] = rt_current_pcr_resp.as_bytes().try_into().unwrap();

    let cptra_config_init_vals_hash: [u8; 48] =
        calculate_cptra_config_init_vals_hash(&mut model, &updated_fw_image);

    // We don't expect the image_digest to be part of the stash
    let mut hasher = Sha384::new();
    hasher.update(rt_current_pcr);
    hasher.update(cptra_config_init_vals_hash);
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
        crate::test_update_reset::mbox_test_image(),
        image_options,
    )
    .unwrap();

    // trigger an update reset so we can use commands in mbox responder
    model
        .mailbox_execute(
            u32::from(CommandId::FIRMWARE_LOAD),
            &updated_fw_image.to_bytes().unwrap(),
        )
        .unwrap();

    let rt_current_pcr_resp = model.mailbox_execute(0x1000_0001, &[]).unwrap().unwrap();
    let rt_current_pcr: [u8; 48] = rt_current_pcr_resp.as_bytes().try_into().unwrap();

    let cptra_config_init_vals_hash: [u8; 48] =
        calculate_cptra_config_init_vals_hash(&mut model, &updated_fw_image);

    // hash expected DPE measurements in order to check that stashed measurement was added to DPE
    let mut hasher = Sha384::new();
    hasher.update(rt_current_pcr);
    hasher.update(cptra_config_init_vals_hash);
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

fn get_mcu_image_metadata(mcu_image: &[u8]) -> AuthManifestImageMetadata {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_exec_bit(2);
    let mut hasher = Sha384::new();
    hasher.update(mcu_image);
    let fw_digest = hasher.finalize();

    AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_2),
        flags: flags.0,
        digest: fw_digest.into(),
        image_staging_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        image_load_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    }
}

#[cfg(feature = "fpga_subsystem")]
pub fn write_mcu_mbox_sram(model: &mut DefaultHwModel, data: &[u8]) {
    println!("locking  MCU mailbox SRAMs");
    unsafe {
        // Make sure the SRAMs are unlocked.
        // In case SRAM is locked from a previous test, we need to unlock it first
        // by writing 0 to the exec register.
        // If it's already unlocked, this is a no-op
        let mcu_mbox_exec_ptr = model.mmio.mci().unwrap().ptr.add(0x600018 / 4) as *mut u32;
        mcu_mbox_exec_ptr.write_volatile(0x0);

        // Read from the lock register to the lock the SRAM
        let mcu_mbox_lock_ptr = model.mmio.mci().unwrap().ptr.add(0x600000 / 4) as *mut u32;
        loop {
            let lock = mcu_mbox_lock_ptr.read_volatile();
            if lock & 0x1 == 0 {
                break;
            }
        }
    };

    println!("Writing MCU mailbox SRAMs");
    unsafe {
        let mcu_mbox_sram_ptr = model.mmio.mci().unwrap().ptr.add(0x400000 / 4) as *mut u32;

        for (count, chunk) in data.chunks(4).enumerate() {
            mcu_mbox_sram_ptr
                .offset(count as isize)
                .write_volatile(u32::from_be_bytes(chunk.try_into().unwrap()));
        }
    };
}

fn write_to_test_sram(model: &mut DefaultHwModel, address: Addr64, data: &[u8]) {
    // For FPGA testing, we'll use the MCU mailbox SRAMs to simulate the test SRAM.
    #[cfg(feature = "fpga_subsystem")]
    {
        let staging_address = address.lo as usize - TEST_SRAM_BASE.lo as usize;
        let mut test_sram_contents = vec![0u8; TEST_SRAM_SIZE];
        let image_size = data.len();
        test_sram_contents[staging_address..staging_address + image_size].copy_from_slice(data);

        write_mcu_mbox_sram(model, &test_sram_contents);
    }
    #[cfg(not(feature = "fpga_subsystem"))]
    {
        let _ = model;
        let _ = address;
        let _ = data;
    }
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_authorize_from_load_address() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let mut hasher = Sha384::new();
    hasher.update(load_memory_contents);
    let fw_digest = hasher.finalize();

    let image_metadata = AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: fw_digest.into(),
        image_load_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    };
    let mcu_image = {
        let mut arr = [0u8; 256];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as u8;
        }
        arr
    };

    let mcu_image_metadata = get_mcu_image_metadata(&mcu_image);
    let auth_manifest =
        create_auth_manifest_with_metadata([mcu_image_metadata, image_metadata].to_vec());
    let mut model =
        set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents, &mcu_image);

    write_to_test_sram(
        &mut model,
        image_metadata.image_load_address,
        &load_memory_contents,
    );
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

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_authorize_from_load_address_incorrect_digest() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let image_metadata = AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: [0; 48],
        image_load_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    };
    let mcu_image = [0xAAu8; 256];
    let mcu_image_metadata = get_mcu_image_metadata(&mcu_image);
    let auth_manifest =
        create_auth_manifest_with_metadata([mcu_image_metadata, image_metadata].to_vec());

    let mut model =
        set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents, &mcu_image);
    write_to_test_sram(
        &mut model,
        image_metadata.image_load_address,
        &load_memory_contents,
    );
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

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_authorize_from_staging_address() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::StagingAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let mut hasher = Sha384::new();
    hasher.update(load_memory_contents);
    let fw_digest = hasher.finalize();

    let image_metadata = AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: fw_digest.into(),
        image_staging_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    };
    let mcu_image = [0xAAu8; 256];
    let mcu_image_metadata = get_mcu_image_metadata(&mcu_image);
    let auth_manifest =
        create_auth_manifest_with_metadata([mcu_image_metadata, image_metadata].to_vec());

    let mut model =
        set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents, &mcu_image);
    write_to_test_sram(
        &mut model,
        image_metadata.image_staging_address,
        &load_memory_contents,
    );
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

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_authorize_from_staging_address_incorrect_digest() {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::StagingAddress as u32);

    let load_memory_contents = [0x55u8; 512];
    let image_metadata = AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: [0; 48],
        image_staging_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    };
    let mcu_image = [0xAAu8; 256];
    let mcu_image_metadata = get_mcu_image_metadata(&mcu_image);
    let auth_manifest =
        create_auth_manifest_with_metadata([mcu_image_metadata, image_metadata].to_vec());

    let mut model =
        set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents, &mcu_image);
    write_to_test_sram(
        &mut model,
        image_metadata.image_staging_address,
        &load_memory_contents,
    );
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

    model.step_until_ready_for_runtime();

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

    model.step_until_ready_for_runtime();

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

#[test]
fn test_authorize_and_stash_update_existing_success() {
    // Set up auth manifest and stash initial measurement to create a DPE context
    let mut model = set_auth_manifest(None);

    let mut stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0, // Normal stash (create new context)
        svn: 5,
        ..Default::default()
    });
    stash_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            stash_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(stash_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Update the existing context using UPDATE_EXISTING
    let mut update_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::UPDATE_EXISTING.bits(),
        svn: 10,
        ..Default::default()
    });
    update_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            update_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let update_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(update_resp.auth_req_result, IMAGE_AUTHORIZED);
}

#[test]
fn test_authorize_and_stash_update_existing_no_context_fails() {
    // Set up auth manifest but do NOT stash any measurement first
    let mut model = set_auth_manifest(None);

    // Try to update a non-existent context — should fail
    let mut update_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::UPDATE_EXISTING.bits(),
        svn: 5,
        ..Default::default()
    });
    update_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(
        u32::from(CommandId::AUTHORIZE_AND_STASH),
        update_cmd.as_bytes().unwrap(),
    );

    // Should fail because no existing context with this TCI type
    assert!(resp.is_err() || resp.unwrap().is_none());
}

#[test]
fn test_authorize_and_stash_update_existing_mcfw_success() {
    // Test UPDATE_EXISTING with MCU FW TCI type ("MCFW") — the hitless update path
    let mut model = set_auth_manifest(None);

    // First: stash an MCU FW measurement (fw_id 2 triggers "MCFW" TCI type)
    let mut stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0,
        svn: 3,
        ..Default::default()
    });
    stash_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            stash_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(stash_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Update with MCFW TCI type and new SVN
    let mut update_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::UPDATE_EXISTING.bits(),
        svn: 7,
        ..Default::default()
    });
    update_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            update_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");

    let update_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(update_resp.auth_req_result, IMAGE_AUTHORIZED);
}

#[test]
fn test_authorize_and_stash_update_existing_verifies_dpe_state() {
    // Verify that UPDATE_EXISTING (RECURSIVE DeriveContext) actually updates the
    // DPE context's TCI measurements, not just returns success.
    let mut model = set_auth_manifest(None);

    const MCFW_TAG: u32 = 42;

    // Step 1: Stash initial MCU FW measurement (fw_id 2 → "MCFW" TCI type)
    let mut stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: 0,
        svn: 3,
        ..Default::default()
    });
    stash_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            stash_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Stash should return a response");
    let stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(stash_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Step 2: Tag the stashed context (it's now the default in this locality)
    let mut tag_cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: MCFW_TAG,
    });
    tag_cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::DPE_TAG_TCI),
            tag_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Tag should return a response");

    // Step 3: Read initial TCI state
    let mut get_tci_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: MCFW_TAG,
    });
    get_tci_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_tci_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("GetTaggedTci should return a response");
    let tci_resp = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();

    // After initial stash: tci_current = IMAGE_DIGEST1
    assert_eq!(tci_resp.tci_current, IMAGE_DIGEST1);

    // tci_cumulative = SHA384([0u8; 48] || IMAGE_DIGEST1)
    let mut hasher = Sha384::new();
    hasher.update([0u8; 48]);
    hasher.update(IMAGE_DIGEST1);
    let expected_initial_cumulative: [u8; 48] = hasher.finalize().into();
    assert_eq!(tci_resp.tci_cumulative, expected_initial_cumulative);

    // Step 4: UPDATE_EXISTING with a different measurement
    let mut update_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_2,
        measurement: IMAGE_DIGEST2,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::UPDATE_EXISTING.bits(),
        svn: 7,
        ..Default::default()
    });
    update_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            update_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Update should return a response");
    let update_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(update_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Step 5: Read DPE state after RECURSIVE update
    let mut get_tci_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: MCFW_TAG,
    });
    get_tci_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_tci_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("GetTaggedTci should return a response");
    let tci_resp = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();

    // After RECURSIVE update: tci_current = IMAGE_DIGEST2
    assert_eq!(tci_resp.tci_current, IMAGE_DIGEST2);

    // tci_cumulative = SHA384(old_cumulative || IMAGE_DIGEST2)
    let mut hasher = Sha384::new();
    hasher.update(expected_initial_cumulative);
    hasher.update(IMAGE_DIGEST2);
    let expected_updated_cumulative: [u8; 48] = hasher.finalize().into();
    assert_eq!(tci_resp.tci_cumulative, expected_updated_cumulative);
}

#[cfg_attr(feature = "fpga_realtime", ignore)]
#[test]
fn test_update_existing_from_load_address_verifies_dpe_state() {
    // Verify that UPDATE_EXISTING with LoadAddress source stashes the computed
    // measurement (not zeros) into the DPE context.
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::LoadAddress as u32);

    let load_memory_contents = [0x55u8; 512];

    let mut hasher = Sha384::new();
    hasher.update(load_memory_contents);
    let fw_digest: [u8; 48] = hasher.finalize().into();

    let image_metadata = AuthManifestImageMetadata {
        fw_id: u32::from_le_bytes(FW_ID_1),
        flags: flags.0,
        digest: fw_digest,
        image_load_address: Addr64 {
            lo: TEST_SRAM_BASE.lo,
            hi: TEST_SRAM_BASE.hi,
        },
        ..Default::default()
    };
    let mcu_image = {
        let mut arr = [0u8; 256];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as u8;
        }
        arr
    };

    let mcu_image_metadata = get_mcu_image_metadata(&mcu_image);
    let auth_manifest =
        create_auth_manifest_with_metadata([mcu_image_metadata, image_metadata].to_vec());
    let mut model =
        set_auth_manifest_with_test_sram(Some(auth_manifest), &load_memory_contents, &mcu_image);

    // Step 1: Initial stash with InRequest to create the DPE context
    write_to_test_sram(
        &mut model,
        image_metadata.image_load_address,
        &load_memory_contents,
    );
    let mut stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: fw_digest,
        source: ImageHashSource::InRequest as u32,
        flags: 0,
        svn: 5,
        ..Default::default()
    });
    stash_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            stash_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Stash should return a response");
    let stash_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(stash_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Step 2: Tag the context
    const LOAD_TAG: u32 = 99;
    let mut tag_cmd = MailboxReq::TagTci(TagTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        handle: [0u8; 16],
        tag: LOAD_TAG,
    });
    tag_cmd.populate_chksum().unwrap();
    model
        .mailbox_execute(
            u32::from(CommandId::DPE_TAG_TCI),
            tag_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Tag should return a response");

    // Step 3: Read initial TCI
    let mut get_tci_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: LOAD_TAG,
    });
    get_tci_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_tci_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("GetTaggedTci should return a response");
    let tci_resp = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(tci_resp.tci_current, fw_digest);

    let mut hasher = Sha384::new();
    hasher.update([0u8; 48]);
    hasher.update(fw_digest);
    let expected_initial_cumulative: [u8; 48] = hasher.finalize().into();
    assert_eq!(tci_resp.tci_cumulative, expected_initial_cumulative);

    // Step 4: UPDATE_EXISTING with LoadAddress — measurement should be computed
    // from memory, not from the zeros in cmd.measurement
    write_to_test_sram(
        &mut model,
        image_metadata.image_load_address,
        &load_memory_contents,
    );
    let mut update_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: FW_ID_1,
        measurement: [0; 48], // zeros — LoadAddress should compute the real digest
        source: ImageHashSource::LoadAddress as u32,
        flags: AuthAndStashFlags::UPDATE_EXISTING.bits(),
        image_size: load_memory_contents.len() as u32,
        svn: 10,
        ..Default::default()
    });
    update_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            update_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("Update should return a response");
    let update_resp = AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap();
    assert_eq!(update_resp.auth_req_result, IMAGE_AUTHORIZED);

    // Step 5: Verify DPE was updated with the computed digest, not zeros
    let mut get_tci_cmd = MailboxReq::GetTaggedTci(GetTaggedTciReq {
        hdr: MailboxReqHeader { chksum: 0 },
        tag: LOAD_TAG,
    });
    get_tci_cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DPE_GET_TAGGED_TCI),
            get_tci_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("GetTaggedTci should return a response");
    let tci_resp = GetTaggedTciResp::read_from_bytes(resp.as_slice()).unwrap();

    // tci_current should be the computed digest (fw_digest), NOT zeros
    assert_eq!(tci_resp.tci_current, fw_digest);
    assert_ne!(
        tci_resp.tci_current, [0u8; 48],
        "DPE must not be extended with zeros"
    );

    // tci_cumulative = SHA384(initial_cumulative || fw_digest)
    let mut hasher = Sha384::new();
    hasher.update(expected_initial_cumulative);
    hasher.update(fw_digest);
    let expected_updated_cumulative: [u8; 48] = hasher.finalize().into();
    assert_eq!(tci_resp.tci_cumulative, expected_updated_cumulative);
}
