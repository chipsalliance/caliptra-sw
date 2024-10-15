// Licensed under the Apache-2.0 license

use crate::common::{assert_error, run_rt_test_lms};
use caliptra_api::SocManager;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorConfig, AuthManifestGeneratorKeyConfig,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestPrivKeys, AuthManifestPubKeys, AuthorizationManifest,
};
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, SetAuthManifestReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::HwModel;
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::*;
use caliptra_runtime::RtBootStatus;
use zerocopy::AsBytes;

pub fn generate_auth_manifest(flags: AuthManifestFlags) -> AuthorizationManifest {
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
        version: 1,
        flags,
    };

    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate(&gen_config).unwrap()
}

#[test]
fn test_set_auth_manifest_cmd() {
    let mut model = run_rt_test_lms(None, None, None, true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    let buf = auth_manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_SIZE];
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
    let mut model = run_rt_test_lms(None, None, None, true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut set_auth_manifest_cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: 0xffff_ffff,
        manifest: [0u8; SetAuthManifestReq::MAX_SIZE],
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
        manifest: [0u8; SetAuthManifestReq::MAX_SIZE],
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
    let mut model = run_rt_test_lms(None, None, None, true);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let buf = manifest.as_bytes();
    let mut auth_manifest_slice = [0u8; SetAuthManifestReq::MAX_SIZE];
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
fn test_set_auth_manifest_invalid_preamble_marker() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.marker = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER,
    );
}

#[test]
fn test_set_auth_manifest_invalid_preamble_size() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.size -= 1;
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_ecc_sig() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .vendor_man_pub_keys_signatures
        .ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_lms_sig() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest
        .preamble
        .vendor_man_pub_keys_signatures
        .lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_ecc_sig() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.owner_man_pub_keys_signatures.ecc_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_lms_sig() {
    let mut auth_manifest = generate_auth_manifest(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED);
    auth_manifest.preamble.owner_man_pub_keys_signatures.lms_sig = Default::default();
    test_manifest_expect_err(
        auth_manifest,
        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
    );
}
