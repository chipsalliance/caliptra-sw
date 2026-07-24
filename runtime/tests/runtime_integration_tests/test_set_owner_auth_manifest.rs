// Licensed under the Apache-2.0 license

//! Integration tests for `SET_OWNER_AUTH_MANIFEST` and the
//! `AUTHORIZE_AND_STASH` owner-only fall-through path.

use crate::common::{run_rt_test, RuntimeTestArgs};
use crate::test_authorize_and_stash::{set_auth_manifest, FW_ID_1, IMAGE_DIGEST1};
use crate::test_set_auth_manifest::create_auth_manifest_with_metadata;
use caliptra_api::{mailbox::VerifyAuthManifestReq, SocManager};
use caliptra_auth_man_gen::{
    AuthManifestGenerator, AuthManifestGeneratorKeyConfig, OwnerAuthManifestGeneratorConfig,
};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestPrivKeysConfig, AuthManifestPubKeysConfig,
    AuthorizationManifest, ImageMetadataFlags, OwnerAuthorizationManifest,
};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader, SetAuthManifestReq, SetOwnerAuthManifestReq,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel, ModelError};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::{
    OWNER_ECC_KEY_PRIVATE, OWNER_ECC_KEY_PUBLIC, OWNER_LMS_KEY_PRIVATE, OWNER_LMS_KEY_PUBLIC,
    OWNER_MLDSA_KEY_PRIVATE, OWNER_MLDSA_KEY_PUBLIC,
};
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::{
    RtBootStatus, IMAGE_AUTHORIZED_OWNER_ONLY, IMAGE_AUTHORIZED_VENDOR_OWNER, IMAGE_HASH_MISMATCH,
    IMAGE_NOT_AUTHORIZED,
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
    svn: u32,
) -> OwnerAuthorizationManifest {
    let owner_key_config = owner_key_config();
    let gen = AuthManifestGenerator::new(Crypto::default());
    gen.generate_owner(&OwnerAuthManifestGeneratorConfig {
        version: 1,
        svn,
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
    set_owner_auth_manifest(model, man)
        .unwrap()
        .expect("SET_OWNER_AUTH_MANIFEST should return a response");
}

fn set_owner_auth_manifest(
    model: &mut DefaultHwModel,
    man: &OwnerAuthorizationManifest,
) -> Result<Option<Vec<u8>>, ModelError> {
    let buf = man.as_bytes();
    let mut slice = [0u8; SetOwnerAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::SetOwnerAuthManifest(SetOwnerAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    model.mailbox_execute(
        u32::from(CommandId::SET_OWNER_AUTH_MANIFEST),
        cmd.as_bytes().unwrap(),
    )
}

fn set_vendor_owner_auth_manifest(
    model: &mut DefaultHwModel,
    man: &AuthorizationManifest,
) -> Result<Option<Vec<u8>>, ModelError> {
    let buf = man.as_bytes();
    let mut slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::SetAuthManifest(SetAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    model.mailbox_execute(
        u32::from(CommandId::SET_AUTH_MANIFEST),
        cmd.as_bytes().unwrap(),
    )
}

fn verify_vendor_owner_auth_manifest(
    model: &mut DefaultHwModel,
    man: &AuthorizationManifest,
) -> Result<Option<Vec<u8>>, ModelError> {
    let buf = man.as_bytes();
    let mut slice = [0u8; SetAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::VerifyAuthManifest(VerifyAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: buf.len() as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    model.mailbox_execute(
        u32::from(CommandId::VERIFY_AUTH_MANIFEST),
        cmd.as_bytes().unwrap(),
    )
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

    let owner_man = build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
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

#[test]
fn test_set_owner_auth_manifest_rejects_vendor_owner_fw_id() {
    let mut model = set_auth_manifest(None);

    let initial_owner_man =
        build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
    send_set_owner_auth_manifest(&mut model, &initial_owner_man);

    let colliding_owner_man = build_owner_manifest(
        vec![make_entry(u32::from_le_bytes(FW_ID_1), OWNER_ONLY_DIGEST)],
        1,
    );
    let err = set_owner_auth_manifest(&mut model, &colliding_owner_man)
        .expect_err("owner-only fw_id collision must be rejected");
    let expected: u32 = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_DUPLICATE_FW_ID.into();
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected owner manifest duplicate firmware ID, got {err:?}",
    );

    let resp = authorize_and_stash_in_request(
        &mut model,
        OWNER_ONLY_FW_ID.to_le_bytes(),
        OWNER_ONLY_DIGEST,
    );
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);

    let resp = authorize_and_stash_in_request(&mut model, FW_ID_1, IMAGE_DIGEST1);
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_VENDOR_OWNER);
}

#[test]
fn test_verify_and_set_auth_manifest_reject_owner_only_fw_id() {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_image_options: Some(ImageOptions {
            pqc_key_type: FwVerificationPqcKeyType::LMS,
            ..Default::default()
        }),
        ..Default::default()
    });
    model.step_until_ready_for_runtime();

    let owner_man = build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
    send_set_owner_auth_manifest(&mut model, &owner_man);

    let vendor_owner_man = create_auth_manifest_with_metadata(vec![
        make_entry(OWNER_ONLY_FW_ID, IMAGE_DIGEST1),
        make_entry(u32::from_le_bytes(FW_ID_1), IMAGE_DIGEST1),
    ]);
    let expected: u32 =
        CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_DUPLICATE_FIRMWARE_ID.into();

    let err = verify_vendor_owner_auth_manifest(&mut model, &vendor_owner_man)
        .expect_err("verifying a colliding vendor + owner fw_id must fail");
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected auth manifest duplicate firmware ID, got {err:?}",
    );

    let err = set_vendor_owner_auth_manifest(&mut model, &vendor_owner_man)
        .expect_err("vendor + owner fw_id collision must be rejected");
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected auth manifest duplicate firmware ID, got {err:?}",
    );

    let resp = authorize_and_stash_in_request(
        &mut model,
        OWNER_ONLY_FW_ID.to_le_bytes(),
        OWNER_ONLY_DIGEST,
    );
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);

    let resp = authorize_and_stash_in_request(&mut model, FW_ID_1, IMAGE_DIGEST1);
    assert_eq!(resp.auth_req_result, IMAGE_NOT_AUTHORIZED);
}

/// Verify that loading a second manifest replaces the owner-only collection.
#[test]
fn test_set_owner_auth_manifest_replaces_collection() {
    let mut model = set_auth_manifest(None);

    let second_fw_id = OWNER_ONLY_FW_ID + 1;
    let mut second_digest = OWNER_ONLY_DIGEST;
    second_digest[0] ^= 0xFF;

    // Initial load with two entries.
    let owner_man_a = build_owner_manifest(
        vec![
            make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST),
            make_entry(second_fw_id, second_digest),
        ],
        1,
    );
    send_set_owner_auth_manifest(&mut model, &owner_man_a);

    // Replace the collection with one entry carrying a new digest.
    let mut updated_digest = OWNER_ONLY_DIGEST;
    updated_digest[1] ^= 0xFF;
    let owner_man_b = build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, updated_digest)], 1);
    send_set_owner_auth_manifest(&mut model, &owner_man_b);

    // The old digest is no longer authorized for the updated entry.
    let resp = authorize_and_stash_in_request(
        &mut model,
        OWNER_ONLY_FW_ID.to_le_bytes(),
        OWNER_ONLY_DIGEST,
    );
    assert_eq!(resp.auth_req_result, IMAGE_HASH_MISMATCH);

    // The replacement digest is authorized.
    let resp =
        authorize_and_stash_in_request(&mut model, OWNER_ONLY_FW_ID.to_le_bytes(), updated_digest);
    assert_eq!(resp.auth_req_result, IMAGE_AUTHORIZED_OWNER_ONLY);

    // The second entry was removed by the replacement.
    let resp =
        authorize_and_stash_in_request(&mut model, second_fw_id.to_le_bytes(), second_digest);
    assert_eq!(resp.auth_req_result, IMAGE_NOT_AUTHORIZED);
}

/// The former update bit is reserved and must be rejected.
#[test]
fn test_set_owner_auth_manifest_rejects_nonzero_flags() {
    let mut model = set_auth_manifest(None);
    let mut owner_man =
        build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
    owner_man.preamble.flags = 1;

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

    let err = result.expect_err("nonzero owner manifest flags must be rejected");
    let expected: u32 = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_INVALID_FLAGS.into();
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected RUNTIME_OWNER_AUTH_MANIFEST_INVALID_FLAGS, got {err:?}",
    );
}

/// The embedded size covers the owner manifest Preamble.
#[test]
fn test_set_owner_auth_manifest_rejects_invalid_preamble_size() {
    let mut model = set_auth_manifest(None);
    let mut owner_man =
        build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
    owner_man.preamble.size -= 1;

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

    let err = result.expect_err("incorrect owner manifest Preamble size must be rejected");
    let expected: u32 = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH.into();
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected RUNTIME_OWNER_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH, got {err:?}",
    );
}

/// The mailbox payload length must match the complete serialized manifest.
#[test]
fn test_set_owner_auth_manifest_rejects_truncated_manifest() {
    let mut model = set_auth_manifest(None);
    let owner_man = build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);

    let buf = owner_man.as_bytes();
    let mut slice = [0u8; SetOwnerAuthManifestReq::MAX_MAN_SIZE];
    slice[..buf.len()].copy_from_slice(buf);

    let mut cmd = MailboxReq::SetOwnerAuthManifest(SetOwnerAuthManifestReq {
        hdr: MailboxReqHeader { chksum: 0 },
        manifest_size: (buf.len() - 1) as u32,
        manifest: slice,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        u32::from(CommandId::SET_OWNER_AUTH_MANIFEST),
        cmd.as_bytes().unwrap(),
    );

    let err = result.expect_err("truncated owner manifest must be rejected");
    let expected: u32 = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE.into();
    assert!(
        matches!(err, ModelError::MailboxCmdFailed(code) if code == expected),
        "expected RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE, got {err:?}",
    );
}

/// Bad marker is rejected with the dedicated error.
#[test]
fn test_set_owner_auth_manifest_invalid_marker() {
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

    let mut owner_man =
        build_owner_manifest(vec![make_entry(OWNER_ONLY_FW_ID, OWNER_ONLY_DIGEST)], 1);
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
