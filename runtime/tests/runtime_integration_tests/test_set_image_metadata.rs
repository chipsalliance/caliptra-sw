// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test_lms};
use crate::test_set_auth_manifest::generate_auth_manifest;
use caliptra_auth_man_gen::{AuthManifestGeneratorKeyConfig, ImcGenerator, ImcGeneratorConfig};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestImageMetadataSetHeader,
    AuthManifestImageMetadataWithSignatures, AuthManifestPrivKeys, AuthManifestPubKeys,
    AuthManifestSignatures, ImageMetadataFlags,
};
use caliptra_common::mailbox_api::{
    CommandId, ImageHashSource, MailboxReq, MailboxReqHeader, SetAuthManifestReq,
    SetImageMetadataReq,
};
use caliptra_drivers::AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_runtime::RtBootStatus;
use core::mem::size_of;
use zerocopy::AsBytes;

const IMAGE_METADATA_CONST_SIZE: usize =
    size_of::<AuthManifestSignatures>() * 2 + size_of::<AuthManifestImageMetadataSetHeader>();

pub const IMAGE_DIGEST1: [u8; 48] = [
    0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];

pub const IMAGE_DIGEST2: [u8; 48] = [
    0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50, 0x07,
    0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF, 0x5B, 0xED,
    0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34, 0xC8, 0x25, 0xA7,
];

pub const IMAGE_DIGEST3: [u8; 48] = [
    0xCC, 0x01, 0x74, 0x3E, 0x44, 0xA2, 0x5F, 0x8A, 0xB4, 0xA1, 0x3C, 0x68, 0x9B, 0xC7, 0x51, 0x06,
    0x26, 0x2D, 0x33, 0xAA, 0x0F, 0xDF, 0xD0, 0x62, 0x19, 0x8A, 0x61, 0x5B, 0x42, 0xFE, 0x5A, 0xEC,
    0x81, 0x87, 0x06, 0x2A, 0xA0, 0xE6, 0xCD, 0x22, 0x59, 0xBB, 0xED, 0xA0, 0x35, 0xC9, 0x24, 0xA6,
];

pub fn generate_image_metadata(
    flags: AuthManifestFlags,
) -> AuthManifestImageMetadataWithSignatures {
    let vendor_man_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_1_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_1_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_1_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_1_PRIVATE,
        }),
    };

    let owner_man_key_info: Option<AuthManifestGeneratorKeyConfig> =
        Some(AuthManifestGeneratorKeyConfig {
            pub_keys: AuthManifestPubKeys {
                ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
                lms_pub_key: OWNER_LMS_KEY_PUBLIC,
            },
            priv_keys: Some(AuthManifestPrivKeys {
                ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
                lms_priv_key: OWNER_LMS_KEY_PRIVATE,
            }),
        });

    // Generate authorization manifest.
    let mut flags1 = ImageMetadataFlags(0);
    flags1.set_image_source(ImageHashSource::InRequest as u32);
    flags1.set_ignore_auth_check(false);

    let mut flags2 = ImageMetadataFlags(0);
    flags2.set_image_source(ImageHashSource::ShaAcc as u32);
    flags2.set_ignore_auth_check(true);

    let mut flags3 = ImageMetadataFlags(0);
    flags3.set_image_source(ImageHashSource::InRequest as u32);
    flags3.set_ignore_auth_check(false);

    let image_metadata_list: Vec<AuthManifestImageMetadata> = vec![
        AuthManifestImageMetadata {
            fw_id: 1,
            flags: flags1.0,
            digest: IMAGE_DIGEST1,
        },
        AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags2.0,
            digest: IMAGE_DIGEST2,
        },
        AuthManifestImageMetadata {
            fw_id: 3,
            flags: flags3.0,
            digest: IMAGE_DIGEST3,
        },
    ];

    let gen_config: ImcGeneratorConfig = ImcGeneratorConfig {
        vendor_man_key_info,
        owner_man_key_info,
        revision: 1,
        flags,
        image_metadata_list,
    };

    let gen = ImcGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

pub fn get_ims_actual_size(ims: &AuthManifestImageMetadataWithSignatures) -> usize {
    IMAGE_METADATA_CONST_SIZE
        + size_of::<AuthManifestImageMetadata>() * ims.image_metadata.header.entry_count as usize
}

fn test_metadata(
    payload: &[u8],
    expected_err: Option<CaliptraError>,
    model: Option<&mut DefaultHwModel>,
) {
    let mut model_instance: Option<DefaultHwModel>;

    let model = if model.is_none() {
        model_instance = Some(run_rt_test_lms(None, None, None, true));

        if let Some(ref mut instance) = model_instance {
            instance.step_until(|m| {
                m.soc_ifc().cptra_boot_status().read()
                    == u32::from(RtBootStatus::RtReadyForCommands)
            });
        }
        model_instance.as_mut()
    } else {
        model
    };

    let model = model.unwrap();

    let mut ims_slice = [0u8; SetImageMetadataReq::MAX_SIZE];
    ims_slice[..payload.len()].copy_from_slice(payload);

    let mut set_image_metadata_cmd = MailboxReq::SetImageMetadata(SetImageMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata_size: payload.len() as u32,
        metadata: ims_slice,
    });
    set_image_metadata_cmd.populate_chksum().unwrap();

    let resp = model.mailbox_execute(
        u32::from(CommandId::SET_IMAGE_METADATA),
        set_image_metadata_cmd.as_bytes().unwrap(),
    );

    if let Some(expected_err) = expected_err {
        assert_error(model, expected_err, resp.unwrap_err());
    } else {
        resp.unwrap().expect("We should have received a response");
    }
}

pub fn send_auth_manifest_cmd(payload: &[u8]) -> DefaultHwModel {
    let mut model = run_rt_test_lms(None, None, None, true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_SIZE];
    auth_manifest_slice[..payload.len()].copy_from_slice(payload);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: payload.len() as u32,
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
fn test_set_image_metadata_invalid_metadata_list_count() {
    let mut ims = generate_image_metadata(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    ims.image_metadata.header.entry_count = 0;
    test_metadata(
        ims.as_bytes(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT),
        None,
    );

    ims.image_metadata.header.entry_count =
        (AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT + 1) as u32;
    test_metadata(
        ims.as_bytes(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT),
        None,
    );
}

#[test]
fn test_set_image_metadata_insufficient_metadata_size() {
    let mut ims = generate_image_metadata(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    let ims_size = get_ims_actual_size(&ims);
    ims.image_metadata.header.entry_count += 1;
    test_metadata(
        ims.as_bytes()[..ims_size].as_ref(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_SET_INVALID_SIZE),
        None,
    );
}

#[test]
fn test_set_image_metadata_invalid_vendor_metadata_ecc_sig() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.vendor_signatures.ecc_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_invalid_vendor_metadata_lms_sig() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.vendor_signatures.lms_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID),
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_invalid_owner_metadata_ecc_sig() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.owner_signatures.ecc_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID),
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_invalid_owner_metadata_lms_sig() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.owner_signatures.lms_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID),
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_success() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let ims = generate_image_metadata(flags);
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        None,
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_invalid_vendor_metadata_ecc_sig_success() {
    let flags = AuthManifestFlags::default();
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.vendor_signatures.ecc_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        None,
        Some(&mut model),
    );
}

#[test]
fn test_set_image_metadata_invalid_vendor_metadata_lms_sig_success() {
    let flags = AuthManifestFlags::default();
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let mut ims = generate_image_metadata(flags);
    ims.vendor_signatures.lms_sig = Default::default();
    test_metadata(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        None,
        Some(&mut model),
    );
}
