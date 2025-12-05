// Licensed under the Apache-2.0 license

use crate::test_activate_firmware::{TEST_SRAM_BASE, TEST_SRAM_SIZE};
use crate::{
    common::{assert_error, run_rt_test_pqc, RuntimeTestArgs, PQC_KEY_TYPE},
    test_authorize_and_stash::IMAGE_DIGEST1,
    test_info::get_fwinfo,
};
use caliptra_api::mailbox::ExternalMailboxCmdReq;
use caliptra_api::{mailbox::ImageHashSource, SocManager};
use caliptra_auth_man_gen::default_test_manifest::{
    create_test_auth_manifest_with_config, create_test_auth_manifest_with_metadata,
};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthorizationManifest, ImageMetadataFlags,
    AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
};
use caliptra_common::mailbox_api::{CommandId, MailboxReq, MailboxReqHeader, SetAuthManifestReq};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_types::FwVerificationPqcKeyType;
use caliptra_runtime::RtBootStatus;
use sha2::{Digest, Sha384};
use zerocopy::IntoBytes;

pub struct AuthManifestBuilderCfg {
    pub manifest_flags: AuthManifestFlags,
    pub pqc_key_type: FwVerificationPqcKeyType,
    pub svn: u32,
}

impl Default for AuthManifestBuilderCfg {
    fn default() -> Self {
        Self {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: FwVerificationPqcKeyType::MLDSA,
            svn: 1,
        }
    }
}

pub fn create_auth_manifest(cfg: &AuthManifestBuilderCfg) -> AuthorizationManifest {
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
    flags2.set_image_source(ImageHashSource::InRequest as u32);

    // Generate authorization manifest.
    let image_metadata_list: Vec<AuthManifestImageMetadata> = vec![
        AuthManifestImageMetadata {
            fw_id: 1,
            flags: flags1.0,
            digest: IMAGE_DIGEST1,
            ..Default::default()
        },
        AuthManifestImageMetadata {
            fw_id: 2,
            flags: flags2.0,
            digest: image_digest2,
            ..Default::default()
        },
    ];

    create_test_auth_manifest_with_config(
        image_metadata_list,
        cfg.manifest_flags,
        cfg.pqc_key_type,
        cfg.svn,
        Crypto::default(),
    )
}

// Default
pub fn create_auth_manifest_with_metadata(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
) -> AuthorizationManifest {
    create_auth_manifest_with_metadata_with_svn(
        image_metadata_list,
        FwVerificationPqcKeyType::LMS,
        1,
    )
}

pub fn create_auth_manifest_with_metadata_with_svn(
    image_metadata_list: Vec<AuthManifestImageMetadata>,
    pqc_key_type: FwVerificationPqcKeyType,
    svn: u32,
) -> AuthorizationManifest {
    create_test_auth_manifest_with_metadata(
        image_metadata_list,
        pqc_key_type,
        svn,
        Crypto::default(),
    )
}

fn create_auth_manifest_of_metadata_size(
    metadata_size: usize,
    pqc_key_type: FwVerificationPqcKeyType,
) -> AuthorizationManifest {
    let mut flags = ImageMetadataFlags(0);
    flags.set_ignore_auth_check(true);
    flags.set_image_source(ImageHashSource::InRequest as u32);
    let mut digest = crate::test_authorize_and_stash::IMAGE_DIGEST1;

    // Generate authorization manifest with a specific amount of elements.
    let mut image_metadata_list = Vec::new();
    for id in 0..metadata_size {
        digest[0] = id as u8;
        image_metadata_list.push(AuthManifestImageMetadata {
            fw_id: id as u32,
            flags: flags.0,
            digest,
            ..Default::default()
        })
    }

    create_test_auth_manifest_with_metadata(image_metadata_list, pqc_key_type, 1, Crypto::default())
}

#[test]
#[cfg(not(feature = "fpga_realtime"))] // subsystem only
fn test_set_auth_manifest_cmd_external() {
    let auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
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
    let set_auth_manifest_cmd = set_auth_manifest_cmd.as_bytes().unwrap();

    let mut external_mailbox_cmd = MailboxReq::ExternalMailboxCmd(ExternalMailboxCmdReq {
        command_id: u32::from(CommandId::SET_AUTH_MANIFEST),
        command_size: set_auth_manifest_cmd.len() as u32,
        axi_address_start_low: TEST_SRAM_BASE.lo,
        axi_address_start_high: TEST_SRAM_BASE.hi,
        ..Default::default()
    });
    external_mailbox_cmd.populate_chksum().unwrap();
    let mut test_sram = [0u8; TEST_SRAM_SIZE];
    test_sram[..set_auth_manifest_cmd.len()].copy_from_slice(set_auth_manifest_cmd);

    let mut model = run_rt_test_pqc(
        RuntimeTestArgs {
            subsystem_mode: true,
            test_sram: Some(&test_sram),
            ..Default::default()
        },
        FwVerificationPqcKeyType::LMS,
    );

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    model
        .mailbox_execute(
            u32::from(CommandId::EXTERNAL_MAILBOX_CMD),
            external_mailbox_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
}

#[test]
fn test_set_auth_manifest_cmd_pqc_mldsa() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::MLDSA);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        ..Default::default()
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
fn test_set_auth_manifest_cmd_pqc_lms() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::LMS);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::LMS,
        ..Default::default()
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
fn test_set_auth_manifest_fw_info_digest() {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), FwVerificationPqcKeyType::MLDSA);

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type: FwVerificationPqcKeyType::MLDSA,
        ..Default::default()
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

    let mut hasher = Sha384::new();
    hasher.update(buf);
    let authman_digest = hasher.finalize();

    // Get firmware information
    let info = get_fwinfo(&mut model);

    // Convert to big endian dwords.
    let authman_digest: Vec<u32> = authman_digest
        .as_bytes()
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect();

    assert_eq!(info.authman_sha384_digest, authman_digest.as_slice());
}

#[test]
fn test_set_auth_manifest_cmd_invalid_len() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), *pqc_key_type);

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
}

fn set_manifest_command_execute(
    manifest: AuthorizationManifest,
    pqc_key_type: FwVerificationPqcKeyType,
    expected_err: Option<CaliptraError>,
) {
    let mut model = run_rt_test_pqc(RuntimeTestArgs::default(), pqc_key_type);
    model_set_manifest_command_execute(&mut model, manifest, expected_err);
}

fn model_set_manifest_command_execute(
    model: &mut DefaultHwModel,
    manifest: AuthorizationManifest,
    expected_err: Option<CaliptraError>,
) {
    let buf = manifest.as_bytes();
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
    if let Some(expected_err) = expected_err {
        assert_error(model, expected_err, result.unwrap_err());
    } else {
        result.unwrap().expect("We should have received a response");
    }
}

#[test]
fn test_set_auth_manifest_cmd_zero_metadata_entry() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let auth_manifest = create_auth_manifest_of_metadata_size(0, *pqc_key_type);
        set_manifest_command_execute(
            auth_manifest,
            *pqc_key_type,
            Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT),
        );
    }
}

#[test]
fn test_set_auth_manifest_cmd_max_metadata_entry_limit() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let auth_manifest = create_auth_manifest_of_metadata_size(
            AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
            *pqc_key_type,
        );
        set_manifest_command_execute(auth_manifest, *pqc_key_type, None);
    }
}

#[test]
fn test_set_auth_manifest_cmd_max_plus_one_metadata_entry_limit() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut auth_manifest = create_auth_manifest_of_metadata_size(
            AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
            *pqc_key_type,
        );
        auth_manifest.image_metadata_col.entry_count += 1;

        set_manifest_command_execute(
            auth_manifest,
            *pqc_key_type,
            Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT),
        );
    }
}

#[test]
fn test_set_auth_manifest_invalid_preamble_marker() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        });
        auth_manifest.preamble.marker = Default::default();
        set_manifest_command_execute(
            auth_manifest,
            *pqc_key_type,
            Some(CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER),
        );
    }
}

#[test]
fn test_set_auth_manifest_invalid_preamble_size() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        });
        auth_manifest.preamble.size -= 1;
        set_manifest_command_execute(
            auth_manifest,
            *pqc_key_type,
            Some(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH),
        );
    }
}

#[test]
fn test_set_auth_manifest_invalid_vendor_ecc_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_lms_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.vendor_pub_keys_signatures.pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_mldsa_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.vendor_pub_keys_signatures.pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_ecc_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_lms_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.owner_pub_keys_signatures.pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_mldsa_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest.preamble.owner_pub_keys_signatures.pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE),
    );
}

#[test]
fn test_set_auth_manifest_invalid_metadata_list_count() {
    for pqc_key_type in PQC_KEY_TYPE.iter() {
        let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
            manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        });
        auth_manifest.image_metadata_col.entry_count = 0;
        set_manifest_command_execute(
            auth_manifest,
            *pqc_key_type,
            Some(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT),
        );
    }
}

#[test]
fn test_set_auth_manifest_invalid_vendor_metadata_ecc_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .ecc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_metadata_lms_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_vendor_metadata_mldsa_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_metadata_ecc_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .owner_image_metdata_signatures
        .ecc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_metadata_lms_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .owner_image_metdata_signatures
        .pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID),
    );
}

#[test]
fn test_set_auth_manifest_invalid_owner_metadata_mldsa_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED,
        pqc_key_type,
        ..Default::default()
    });
    auth_manifest
        .preamble
        .owner_image_metdata_signatures
        .pqc_sig = Default::default();
    set_manifest_command_execute(
        auth_manifest,
        pqc_key_type,
        Some(CaliptraError::DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE),
    );
}

#[test]
fn test_set_auth_manifest_cmd_ignore_vendor_ecc_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: 0.into(),
        pqc_key_type,
        ..Default::default()
    });

    // Erase the vendor manifest ECC signature.
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .ecc_sig = Default::default();

    set_manifest_command_execute(auth_manifest, pqc_key_type, None);
}

#[test]
fn test_set_auth_manifest_cmd_ignore_vendor_lms_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::LMS;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: 0.into(),
        pqc_key_type,
        ..Default::default()
    });

    // Erase the vendor manifest LMS signature.
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .pqc_sig = Default::default();

    set_manifest_command_execute(auth_manifest, pqc_key_type, None);
}

#[test]
fn test_set_auth_manifest_cmd_ignore_vendor_mldsa_sig() {
    let pqc_key_type = FwVerificationPqcKeyType::MLDSA;
    let mut auth_manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        manifest_flags: 0.into(),
        pqc_key_type,
        ..Default::default()
    });

    // Erase the vendor manifest LMS signature.
    auth_manifest
        .preamble
        .vendor_image_metdata_signatures
        .pqc_sig = Default::default();

    set_manifest_command_execute(auth_manifest, pqc_key_type, None);
}

#[test]
fn test_set_auth_manifest_with_svn_unprovisioned() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Unprovisioned),
        ),
        soc_manifest_max_svn: Some(127),
        soc_manifest_svn: Some(10),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 1,
        ..Default::default()
    });
    model_set_manifest_command_execute(&mut model, manifest, None);
}

#[test]
fn test_set_auth_manifest_good_svn() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ),
        soc_manifest_max_svn: Some(13),
        soc_manifest_svn: Some(10),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 12,
        ..Default::default()
    });
    model_set_manifest_command_execute(&mut model, manifest, None);
}

#[test]
fn test_set_auth_manifest_svn_gt_max() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ),
        soc_manifest_max_svn: Some(11),
        soc_manifest_svn: Some(10),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 12,
        ..Default::default()
    });
    model_set_manifest_command_execute(
        &mut model,
        manifest,
        Some(CaliptraError::IMAGE_VERIFIER_ERR_FIRMWARE_SVN_GREATER_THAN_MAX_SUPPORTED),
    );
}

#[test]
fn test_set_auth_manifest_svn_lt_fuse() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ),
        soc_manifest_max_svn: Some(127),
        soc_manifest_svn: Some(10),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 1,
        ..Default::default()
    });
    model_set_manifest_command_execute(
        &mut model,
        manifest,
        Some(CaliptraError::IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE),
    );
}

#[test]
fn test_set_auth_manifest_svn_eq_128() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ),
        soc_manifest_max_svn: Some(128),
        soc_manifest_svn: Some(128),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 128,
        ..Default::default()
    });
    model_set_manifest_command_execute(&mut model, manifest, None);
}

#[test]
// Subsystem load soc_manifest via RRI and it will never be to succeed verification
#[cfg(not(feature = "fpga_subsystem"))]
fn test_set_auth_manifest_svn_gt_128() {
    let rt_args = RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Manufacturing),
        ),
        soc_manifest_max_svn: Some(129),
        soc_manifest_svn: Some(129),
        ..Default::default()
    };

    let mut model = run_rt_test_pqc(rt_args, FwVerificationPqcKeyType::default());

    let manifest = create_auth_manifest(&AuthManifestBuilderCfg {
        svn: 129,
        ..Default::default()
    });
    model_set_manifest_command_execute(
        &mut model,
        manifest,
        Some(CaliptraError::IMAGE_VERIFIER_ERR_FIRMWARE_SVN_GREATER_THAN_MAX_SUPPORTED),
    );
}
