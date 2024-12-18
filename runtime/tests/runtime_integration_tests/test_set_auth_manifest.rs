// Licensed under the Apache-2.0 license

use crate::{
    common::{assert_error, run_rt_test_lms, RuntimeTestArgs},
    test_authorize_and_stash::IMAGE_DIGEST1,
};
use caliptra_api::{mailbox::ImageHashSource, SocManager};
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestPrivKeys, AuthManifestPubKeys,
    AuthorizationManifest, ImageMetadataFlags, AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
};
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, SetAuthManifestReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_runtime::RtBootStatus;
use zerocopy::IntoBytes;

pub fn create_auth_manifest(manifest_flags: AuthManifestFlags) -> AuthorizationManifest {
    let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
        }),
    };

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

    let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
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

    let image_digest2: [u8; 48] = [
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50,
        0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF,
        0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34,
        0xC8, 0x25, 0xA7,
    ];

    let mut flags1 = ImageMetadataFlags(0);
    flags1.set_ignore_auth_check(false);
    flags1.set_image_source(ImageHashSource::InRequest as u32);

    let mut flags2 = ImageMetadataFlags(0);
    flags2.set_ignore_auth_check(true);
    flags2.set_image_source(ImageHashSource::ShaAcc as u32);

    // Generate authorization manifest.
    let image_metadata_list: Vec<AuthManifestImageMetadata> = vec![
        AuthManifestImageMetadata {
            fw_id: 1,
            flags: flags1.0,
            digest: IMAGE_DIGEST1,
        },
        AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags2.0,
            digest: image_digest2,
        },
    ];

    let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list,
        version: 1,
        flags: manifest_flags,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

pub fn create_auth_manifest_with_metadata(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
) -> AuthorizationManifest {
    let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
        }),
    };

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

    let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
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

    let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

fn create_auth_manifest_of_metadata_size(metadata_size: usize) -> AuthorizationManifest {
    let vendor_fw_key_info: AuthManifestGeneratorKeyConfig = AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeys {
            ecc_pub_key: VENDOR_ECC_KEY_0_PUBLIC,
            lms_pub_key: VENDOR_LMS_KEY_0_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeys {
            ecc_priv_key: VENDOR_ECC_KEY_0_PRIVATE,
            lms_priv_key: VENDOR_LMS_KEY_0_PRIVATE,
        }),
    };

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

    let owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig> =
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

    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(true);
    flags.set_image_source(ImageHashSource::ShaAcc as u32);
    let mut digest = crate::test_authorize_and_stash::IMAGE_DIGEST1;

    // Generate authorization manifest with a specific amount of elements.
    let mut image_metadata_list = Vec::new();
    for id in 0..metadata_size {
        digest[0] = id as u8;
        image_metadata_list.push(AuthManifestImageMetadata {
            fw_id: id as u32,
            flags: flags.0,
            digest,
        })
    }

    let gen_config: AuthManifestGeneratorConfig = AuthManifestGeneratorConfig {
        vendor_fw_key_info,
        vendor_man_key_info,
        owner_fw_key_info,
        owner_man_key_info,
        image_metadata_list,
        version: 1,
        flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

#[test]
fn test_set_auth_manifest_cmd() {
    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
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
}

#[test]
fn test_set_auth_manifest_cmd_invalid_len() {
    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: 0xffff_ffff,
        manifest: [0u8; SetAuthManifestReq::MAX_MAN_SIZE],
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS,
        resp,
    );

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: 1_u32,
        manifest: [0u8; SetAuthManifestReq::MAX_MAN_SIZE],
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN,
        resp,
    );
}

fn test_manifest_expect_err(manifest: AuthorizationManifest, expected_err: CaliptraError) {
    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let buf = manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: auth_manifest_slice,
    });
    set_auth_manifest_cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::SET_AUTH_MANIFEST),
            set_auth_manifest_cmd.as_bytes().unwrap(),
        )
        .unwrap_err();

    assert_error(&mut model, expected_err, resp);
}

#[test]
fn test_set_auth_manifest_cmd_zero_metadata_entry() {
    let auth_manifest = create_auth_manifest_of_metadata_size(0);
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
    );
}

#[test]
fn test_set_auth_manifest_cmd_max_metadata_entry_limit() {
    let auth_manifest =
        create_auth_manifest_of_metadata_size(AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT);

    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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
}

#[test]
fn test_set_auth_manifest_cmd_max_plus_one_metadata_entry_limit() {
    let mut auth_manifest =
        create_auth_manifest_of_metadata_size(AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT);
    auth_manifest.image_metadata_col.entry_count += 1;

    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(true);
    flags.set_image_source(ImageHashSource::ShaAcc as u32);

    let ptr = auth_manifest
        .image_metadata_col
        .image_metadata_list
        .as_mut_ptr();

    unsafe {
        *ptr.add(AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT) = AuthManifestImageMetadata {
            fw_id: 127,
            flags: flags.0,
            digest: IMAGE_DIGEST1,
        };
    }

    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
    );
}

#[test]
fn test_set_auth_manifest_invalid_preamble_marker() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.marker = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER,
    );
}

#[test]
fn test_set_auth_manifest_invalid_preamble_size() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.size -= 1;
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_ecc_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_lms_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.vendor_pub_keys_signatures.lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_ecc_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_lms_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_metadata_list_count() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.image_metadata_col.entry_count = 0;
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_metadata_ecc_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_metadata_lms_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_metadata_ecc_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .owner_image_metdata_signatures
        .ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_metadata_lms_sig() {
    let mut auth_manifest = create_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .owner_image_metdata_signatures
        .lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_cmd_ignore_vendor_ecc_sig() {
    let mut auth_manifest = create_auth_manifest(0.into());

    // Erase the vendor manifest ECC signature.
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .ecc_sig = Default::default();

    let buf = auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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
}

#[test]
fn test_set_auth_manifest_cmd_ignore_vendor_lms_sig() {
    let mut auth_manifest = create_auth_manifest(0.into());

    // Erase the vendor manifest LMS signature.
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .lms_sig = Default::default();

    let buf = auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    auth_manifest_slice[..buf.len()].copy_from_slice(buf);

    let mut model = run_rt_test_lms(RuntimeTestArgs::default(), true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

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
}
