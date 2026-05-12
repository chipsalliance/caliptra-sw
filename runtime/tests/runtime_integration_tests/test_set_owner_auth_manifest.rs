// Licensed under the Apache-2.0 license

//! Integration tests for `SET_OWNER_AUTH_MANIFEST` and the
//! `AUTHORIZE_AND_STASH` owner-only fall-through path.

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_authorize_and_stash::{set_auth_manifest, FW_ID_1, IMAGE_DIGEST1};
use caliptra_api::SocManager;
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorKeyConfig, OwnerAuthManifestGeneratorConfig,
};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestPrivKeysConfig, AuthManifestPubKeysConfig,
    ImageMetadataFlags, OwnerAuthManifestFlags, OwnerAuthorizationManifest,
};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader, SetOwnerAuthManifestReq,
};
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::{
    OWNER_ECC_KEY_PRIVATE, OWNER_ECC_KEY_PUBLIC, OWNER_LMS_KEY_PRIVATE, OWNER_LMS_KEY_PUBLIC,
    OWNER_MLDSA_KEY_PRIVATE, OWNER_MLDSA_KEY_PUBLIC,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::{
    RtBootStatus, IMAGE_AUTHORIZED_OWNER_ONLY, IMAGE_AUTHORIZED_VENDOR_OWNER, IMAGE_NOT_AUTHORIZED,
};
use zerocopy::{FromBytes, IntoBytes};

/// Owner-only firmware ID (distinct from `FW_ID_1` that lives in the
/// vendor + owner manifest used by `set_auth_manifest`).
const OWNER_ONLY_FW_ID: u32 = 11;

/// A 48-byte digest distinct from `IMAGE_DIGEST1`.
const OWNER_ONLY_DIGEST: [u8; 48] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];

fn owner_key_config() -> AuthManifestGeneratorKeyConfig {
    AuthManifestGeneratorKeyConfig {
        pub_keys: AuthManifestPubKeysConfig {
            ecc_pub_key: OWNER_ECC_KEY_PUBLIC,
            lms_pub_key: OWNER_LMS_KEY_PUBLIC,
            mldsa_pub_key: OWNER_MLDSA_KEY_PUBLIC,
        },
        priv_keys: Some(AuthManifestPrivKeysConfig {
            ecc_priv_key: OWNER_ECC_KEY_PRIVATE,
            lms_priv_key: OWNER_LMS_KEY_PRIVATE,
            mldsa_priv_key: OWNER_MLDSA_KEY_PRIVATE,
        }),
    }
}

/// Build a signed `OwnerAuthorizationManifest` through the shared generator.
fn build_owner_manifest(
    entries: Vec<AuthManifestImageMetadata>,
    flags: OwnerAuthManifestFlags,
    svn: u32,
) -> OwnerAuthorizationManifest {
    let owner_key_config = owner_key_config();
    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate_owner(&OwnerAuthManifestGeneratorConfig {
        version: 1,
        svn,
        flags,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        owner_fw_key_info: owner_key_config.clone(),
        owner_man_key_info: owner_key_config,
        image_metadata_list: entries,
    })
    .unwrap()
}

/// Issue a `SET_OWNER_AUTH_MANIFEST` mailbox command with the
/// supplied owner manifest and assert success.
fn send_set_owner_auth_manifest(model: &mut DefaultHwModel, man: &OwnerAuthorizationManifest) {
    let buf = man.as_bytes();
    let mut slice = [0u8; SetOwnerAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::SetOwnerAuthManifest(SetOwnerAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::SET_OWNER_AUTH_MANIFEST),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("SET_OWNER_AUTH_MANIFEST should return a response");
}

fn make_entry(fw_id: u32, digest: [u8; 48]) -> AuthManifestImageMetadata {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(false);
    flags.set_image_source(ImageHashSource::InRequest as u32);
    AuthManifestImageMetadata {
        fw_id,
        flags: flags.0,
        digest,
        ..Default::default()
    }
}

fn authorize_and_stash_in_request(
    model: &mut DefaultHwModel,
    fw_id_le: [u8; 4],
    measurement: [u8; 48],
) -> AuthorizeAndStashResp {
    let mut cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: fw_id_le,
        measurement,
        source: ImageHashSource::InRequest as u32,
        flags: 0,
        ..Default::default()
    });
    cmd.populate_chksum().unwrap();
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::AUTHORIZE_AND_STASH),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("AUTHORIZE_AND_STASH should return a response");
    AuthorizeAndStashResp::read_from_bytes(resp.as_slice()).unwrap()
}

/// End-to-end: vendor + owner manifest is loaded first, then
/// owner-only manifest is loaded. AUTHORIZE_AND_STASH for a fw_id
/// present only in the owner-only collection returns
/// `IMAGE_AUTHORIZED_OWNER_ONLY`. fw_id present in the vendor + owner
/// collection still returns `IMAGE_AUTHORIZED_VENDOR_OWNER`. Unknown
/// fw_id returns `IMAGE_NOT_AUTHORIZED`.
#[test]
fn test_set_owner_auth_manifest_then_authorize_returns_owner_only() {
    let mut model = set_auth_manifest(None);

    let owner_man = build_owner_manifest(
        vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)],
        OwnerAuthManifestFlags::empty(),
        1,
    );
    send_set_owner_auth_manifest(&mut model, &owner_man);

    // Owner-only collection match.
    let resp = authorize_and_stash_in_request(
        &mut model,
        OWNER_ONLY_FW_ID.to_le_bytes(),
        OWNER_ONLY_DIGEST,
    );
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);

    // Vendor + owner collection still works (FW_ID_1 lives there).
    let resp = authorize_and_stash_in_request(&mut model, FW_ID_1, IMAGE_DIGEST1);
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_VENDOR_OWNER);

    // Unknown fw_id rejects.
    let resp = authorize_and_stash_in_request(&mut model, [0xAB, 0xCD, 0, 0], OWNER_ONLY_DIGEST);
    assert_eq!(resp.auth_req_result, IMAGE_NOT_AUTHORIZED);
}

/// Verify the `APPEND_IMAGE_METADATA` flag merges entries with the
/// existing owner-only collection.
#[test]
fn test_set_owner_auth_manifest_append_flag_merges_entries() {
    let mut model = set_auth_manifest(None);

    // Initial replace-mode load with one entry.
    let owner_man_a = build_owner_manifest(
        vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)],
        OwnerAuthManifestFlags::empty(),
        1,
    );
    send_set_owner_auth_manifest(&mut model, &owner_man_a);

    // Append a second entry.
    let mut second_digest = OWNER_ONLY_DIGEST;
    second_digest[0] ^= 0xFF;
    let owner_man_b = build_owner_manifest(
        vec![make_entry(OWNER_ONLY_FW_ID + 1, second_digest)],
        OwnerAuthManifestFlags::APPEND_IMAGE_METADATA,
        1,
    );
    send_set_owner_auth_manifest(&mut model, &owner_man_b);

    // Both entries must be authorizable.
    let resp = authorize_and_stash_in_request(
        &mut model,
        OWNER_ONLY_FW_ID.to_le_bytes(),
        OWNER_ONLY_DIGEST,
    );
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);

    let resp = authorize_and_stash_in_request(
        &mut model,
        (OWNER_ONLY_FW_ID + 1).to_le_bytes(),
        second_digest,
    );
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);
}

/// Bad marker is rejected with the dedicated error.
#[test]
fn test_set_owner_auth_manifest_invalid_marker() {
    use caliptra_error::CaliptraError;
    use caliptra_hw_model::ModelError;

    let mut model = run_rt_test(RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    });
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut owner_man = build_owner_manifest(
        vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)],
        OwnerAuthManifestFlags::empty(),
        1,
    );
    owner_man.preamble.marker = 0xDEAD_BEEF;

    let buf = owner_man.as_bytes();
    let mut slice = [0u8; SetOwnerAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::SetOwnerAuthManifest(SetOwnerAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::SET_OWNER_AUTH_MANIFEST),
        cmd.as_bytes().unwrap(),
    );

    let err = result.expect_err("invalid marker must be rejected");
    let expected: u32 = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_INVALID_MARKER.into();
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected RUNTIME_OWNER_AUTH_MANIFEST_INVALID_MARKER, got {err:?}",
    );
}
