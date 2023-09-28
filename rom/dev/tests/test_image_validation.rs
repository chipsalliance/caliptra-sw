// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{rom_tests::TEST_FMC_WITH_UART, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_common::memory_layout::{ICCM_ORG, ICCM_SIZE};
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::Array4x12;
use caliptra_drivers::MfgFlags;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, ModelError, SecurityState, U4,
};
use caliptra_image_elf::ElfExecutable;
use caliptra_image_fake_keys::{
    VENDOR_CONFIG_KEY_0, VENDOR_CONFIG_KEY_1, VENDOR_CONFIG_KEY_2, VENDOR_CONFIG_KEY_3,
};
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig, ImageGeneratorVendorConfig};
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::{
    ImageBundle, ImageManifest, VENDOR_ECC_KEY_COUNT, VENDOR_LMS_KEY_COUNT,
};
use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509Req;
use openssl::x509::X509;
use std::str;
use zerocopy::AsBytes;

pub mod helpers;

const ICCM_END_ADDR: u32 = ICCM_ORG + ICCM_SIZE - 1;

const PUB_KEY_X: [u8; 48] = [
    0xD7, 0x9C, 0x6D, 0x97, 0x2B, 0x34, 0xA1, 0xDF, 0xC9, 0x16, 0xA7, 0xB6, 0xE0, 0xA9, 0x9B, 0x6B,
    0x53, 0x87, 0xB3, 0x4D, 0xA2, 0x18, 0x76, 0x07, 0xC1, 0xAD, 0x0A, 0x4D, 0x1A, 0x8C, 0x2E, 0x41,
    0x72, 0xAB, 0x5F, 0xA5, 0xD9, 0xAB, 0x58, 0xFE, 0x45, 0xE4, 0x3F, 0x56, 0xBB, 0xB6, 0x6B, 0xA4,
];

const PUB_KEY_Y: [u8; 48] = [
    0x5A, 0x73, 0x63, 0x93, 0x2B, 0x06, 0xB4, 0xF2, 0x23, 0xBE, 0xF0, 0xB6, 0x0A, 0x63, 0x90, 0x26,
    0x51, 0x12, 0xDB, 0xBD, 0x0A, 0xAE, 0x67, 0xFE, 0xF2, 0x6B, 0x46, 0x5B, 0xE9, 0x35, 0xB4, 0x8E,
    0x45, 0x1E, 0x68, 0xD1, 0x6F, 0x11, 0x18, 0xF2, 0xB3, 0x2B, 0x4C, 0x28, 0x60, 0x87, 0x49, 0xED,
];

const SIGNATURE_R: [u8; 48] = [
    0x93, 0x79, 0x9d, 0x55, 0x12, 0x26, 0x36, 0x28, 0x34, 0xf6, 0xf, 0x7b, 0x94, 0x52, 0x90, 0xb7,
    0xcc, 0xe6, 0xe9, 0x96, 0x1, 0xfb, 0x7e, 0xbd, 0x2, 0x6c, 0x2e, 0x3c, 0x44, 0x5d, 0x3c, 0xd9,
    0xb6, 0x50, 0x68, 0xda, 0xc0, 0xa8, 0x48, 0xbe, 0x9f, 0x5, 0x60, 0xaa, 0x75, 0x8f, 0xda, 0x27,
];

const SIGNATURE_S: [u8; 48] = [
    0xe5, 0x48, 0xe5, 0x35, 0xa1, 0xcc, 0x60, 0xe, 0x13, 0x3b, 0x55, 0x91, 0xae, 0xba, 0xad, 0x78,
    0x5, 0x40, 0x6, 0xd7, 0x52, 0xd0, 0xe1, 0xdf, 0x94, 0xfb, 0xfa, 0x95, 0xd7, 0x8f, 0xb, 0x3f,
    0x8e, 0x81, 0xb9, 0x11, 0x9c, 0x2b, 0xe0, 0x8, 0xbf, 0x6d, 0x6f, 0x4e, 0x41, 0x85, 0xf8, 0x7d,
];

#[test]
fn test_invalid_manifest_marker() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    image_bundle.manifest.marker = 0xDEADBEEF;

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_invalid_manifest_size() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    image_bundle.manifest.size = (core::mem::size_of::<ImageManifest>() - 1) as u32;

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_preamble_zero_vendor_pubkey_digest() {
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0u32; 12],
        ..Default::default()
    };
    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_preamble_vendor_pubkey_digest_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_preamble_owner_pubkey_digest_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_preamble_vendor_ecc_pubkey_revocation() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    const LAST_KEY_IDX: u32 = VENDOR_ECC_KEY_COUNT - 1;
    const VENDOR_CONFIG_LIST: [ImageGeneratorVendorConfig; VENDOR_ECC_KEY_COUNT as usize] = [
        VENDOR_CONFIG_KEY_0,
        VENDOR_CONFIG_KEY_1,
        VENDOR_CONFIG_KEY_2,
        VENDOR_CONFIG_KEY_3,
    ];

    for vendor_config in VENDOR_CONFIG_LIST {
        let mut image_options = ImageOptions::default();
        let key_idx = vendor_config.ecc_key_idx;
        image_options.vendor_config = vendor_config;

        let fuses = caliptra_hw_model::Fuses {
            key_manifest_pk_hash_mask: U4::try_from(
                1u32 << image_options.vendor_config.ecc_key_idx,
            )
            .unwrap(),
            ..Default::default()
        };

        let mut hw = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                ..Default::default()
            },
            fuses,
            ..Default::default()
        })
        .unwrap();

        let image_bundle =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
                .unwrap();

        if key_idx == LAST_KEY_IDX {
            // Last key is never revoked.
            hw.upload_firmware(&image_bundle.to_bytes().unwrap())
                .unwrap();
            hw.step_until_boot_status(ColdResetComplete.into(), true);
        } else {
            assert_eq!(
                ModelError::MailboxCmdFailed(
                    CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED.into()
                ),
                hw.upload_firmware(&image_bundle.to_bytes().unwrap())
                    .unwrap_err()
            );

            assert_eq!(
                hw.soc_ifc().cptra_boot_status().read(),
                FwProcessorManifestLoadComplete.into()
            );
        }
    }
}

#[test]
fn test_preamble_vendor_lms_pubkey_revocation() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    const LAST_KEY_IDX: u32 = VENDOR_LMS_KEY_COUNT - 1;

    for idx in 0..VENDOR_LMS_KEY_COUNT {
        let vendor_config = ImageGeneratorVendorConfig {
            ecc_key_idx: 3,
            lms_key_idx: idx,
            ..VENDOR_CONFIG_KEY_0
        };

        let mut image_options = ImageOptions::default();
        let key_idx = vendor_config.lms_key_idx;
        image_options.vendor_config = vendor_config;

        let fuses = caliptra_hw_model::Fuses {
            lms_verify: true,
            fuse_lms_revocation: 1u32 << image_options.vendor_config.lms_key_idx,
            ..Default::default()
        };

        let mut hw = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                ..Default::default()
            },
            fuses,
            ..Default::default()
        })
        .unwrap();

        let image_bundle =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
                .unwrap();

        if key_idx == LAST_KEY_IDX {
            // Last key is never revoked.
            hw.upload_firmware(&image_bundle.to_bytes().unwrap())
                .unwrap();
            hw.step_until_boot_status(ColdResetComplete.into(), true);
        } else {
            assert_eq!(
                ModelError::MailboxCmdFailed(
                    CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED.into()
                ),
                hw.upload_firmware(&image_bundle.to_bytes().unwrap())
                    .unwrap_err()
            );
        }
    }
}

#[test]
fn test_preamble_vendor_lms_optional_no_pubkey_revocation_check() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    for idx in 0..VENDOR_LMS_KEY_COUNT {
        let vendor_config = ImageGeneratorVendorConfig {
            ecc_key_idx: 3,
            lms_key_idx: idx,
            ..VENDOR_CONFIG_KEY_0
        };
        let image_options = caliptra_builder::ImageOptions {
            vendor_config,
            ..Default::default()
        };

        let fuses = caliptra_hw_model::Fuses {
            lms_verify: false,
            fuse_lms_revocation: 1u32 << image_options.vendor_config.lms_key_idx,
            ..Default::default()
        };

        let mut hw = caliptra_hw_model::new(BootParams {
            init_params: InitParams {
                rom: &rom,
                ..Default::default()
            },
            fuses,
            ..Default::default()
        })
        .unwrap();

        let image_bundle =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
                .unwrap();

        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap();
        hw.step_until_boot_status(ColdResetComplete.into(), true);
    }
}

#[test]
fn test_preamble_vendor_ecc_pubkey_out_of_bounds() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    image_bundle.manifest.preamble.vendor_ecc_pub_key_idx = VENDOR_ECC_KEY_COUNT;

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_preamble_vendor_lms_pubkey_out_of_bounds() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
    image_bundle.manifest.preamble.vendor_lms_pub_key_idx = VENDOR_LMS_KEY_COUNT;

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_OUT_OF_BOUNDS.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );
}

#[test]
fn test_preamble_vendor_lms_optional_no_pubkey_out_of_bounds_check() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
    image_bundle.manifest.preamble.vendor_lms_pub_key_idx = VENDOR_LMS_KEY_COUNT;

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);
}

#[test]
fn test_header_verify_vendor_sig_zero_ecc_pubkey() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_ecc_pub_key_idx = image_bundle.manifest.preamble.vendor_ecc_pub_key_idx as usize;

    // Set ecc_pub_key.x to zero.
    let ecc_pub_key_x_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx].x;
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .x
        .fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );

    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Set ecc_pub_key.y to zero.
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx].x =
        ecc_pub_key_x_backup;
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .y
        .fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_vendor_sig_zero_ecc_signature() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Set vendor_sig.r to zero.
    let vendor_sig_r_backup = image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r;
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r.fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );

    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Set vendor_sig.s to zero.
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r = vendor_sig_r_backup;
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.s.fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_vendor_ecc_sig_mismatch() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_ecc_pub_key_idx = image_bundle.manifest.preamble.vendor_ecc_pub_key_idx as usize;

    // Modify the vendor public key.
    let ecc_pub_key_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx];

    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .x
        .clone_from_slice(Array4x12::from(PUB_KEY_X).0.as_slice());
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .y
        .clone_from_slice(Array4x12::from(PUB_KEY_Y).0.as_slice());

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );

    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Modify the vendor signature.
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx] =
        ecc_pub_key_backup;
    image_bundle
        .manifest
        .preamble
        .vendor_sigs
        .ecc_sig
        .r
        .clone_from_slice(Array4x12::from(SIGNATURE_R).0.as_slice());
    image_bundle
        .manifest
        .preamble
        .vendor_sigs
        .ecc_sig
        .s
        .clone_from_slice(Array4x12::from(SIGNATURE_S).0.as_slice());

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_vendor_lms_sig_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
    let vendor_lms_pub_key_idx = image_bundle.manifest.preamble.vendor_lms_pub_key_idx as usize;

    // Modify the vendor public key.
    let lms_pub_key_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx];

    image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx].digest =
        [Default::default(); 6];
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the vendor signature.
    image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx] =
        lms_pub_key_backup;
    image_bundle.manifest.preamble.vendor_sigs.lms_sig.tree_path[0] = [Default::default(); 6];

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_vendor_lms_optional_no_sig_mismatch_check() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());
    let vendor_lms_pub_key_idx = image_bundle.manifest.preamble.vendor_lms_pub_key_idx as usize;

    // Modify the vendor public key.
    let lms_pub_key_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx];

    image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx].digest =
        [Default::default(); 6];
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the vendor signature.
    image_bundle.manifest.preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx] =
        lms_pub_key_backup;
    image_bundle.manifest.preamble.vendor_sigs.lms_sig.tree_path[0] = [Default::default(); 6];

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);
}

#[test]
fn test_header_verify_owner_lms_sig_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the owner public key.
    let lms_pub_key_backup = image_bundle.manifest.preamble.owner_pub_keys.lms_pub_key;

    image_bundle
        .manifest
        .preamble
        .owner_pub_keys
        .lms_pub_key
        .digest = [Default::default(); 6];
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the owner signature.
    image_bundle.manifest.preamble.owner_pub_keys.lms_pub_key = lms_pub_key_backup;
    image_bundle.manifest.preamble.owner_sigs.lms_sig.tree_path[0] = [Default::default(); 6];

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );
}

#[test]
fn test_header_verify_owner_lms_optional_no_sig_mismatch_check() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the owner public key.
    let lms_pub_key_backup = image_bundle.manifest.preamble.owner_pub_keys.lms_pub_key;

    image_bundle
        .manifest
        .preamble
        .owner_pub_keys
        .lms_pub_key
        .digest = [Default::default(); 6];
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);

    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Modify the owner signature.
    image_bundle.manifest.preamble.owner_pub_keys.lms_pub_key = lms_pub_key_backup;
    image_bundle.manifest.preamble.owner_sigs.lms_sig.tree_path[0] = [Default::default(); 6];

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);
}

#[test]
fn test_header_verify_vendor_ecc_pub_key_in_preamble_and_header() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Change vendor pubkey index.
    image_bundle.manifest.header.vendor_ecc_pub_key_idx =
        image_bundle.manifest.preamble.vendor_ecc_pub_key_idx + 1;
    update_header(&mut image_bundle);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_vendor_lms_pub_key_in_preamble_and_header() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Change vendor pubkey index.
    image_bundle.manifest.header.vendor_lms_pub_key_idx =
        image_bundle.manifest.preamble.vendor_lms_pub_key_idx + 1;
    update_header(&mut image_bundle);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );
}

#[test]
fn test_header_verify_vendor_lms_optional_no_pub_key_in_preamble_and_header_check() {
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: false,
        ..Default::default()
    };
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Change vendor pubkey index.
    image_bundle.manifest.header.vendor_lms_pub_key_idx =
        image_bundle.manifest.preamble.vendor_lms_pub_key_idx + 1;
    update_header(&mut image_bundle);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    hw.step_until_boot_status(ColdResetComplete.into(), true);
}

#[test]
fn test_header_verify_owner_sig_zero_fuses() {
    let image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let fuses = caliptra_hw_model::Fuses::default();

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    assert_eq!(hw.soc_ifc().cptra_fw_error_fatal().read(), 0);
}

#[test]
fn test_header_verify_owner_ecc_sig_zero_pubkey_x() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    // Set ecc_pub_key.x to zero.
    image_bundle
        .manifest
        .preamble
        .owner_pub_keys
        .ecc_pub_key
        .x
        .fill(0);

    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_owner_ecc_sig_zero_pubkey_y() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    // Set ecc_pub_key.y to zero.
    image_bundle
        .manifest
        .preamble
        .owner_pub_keys
        .ecc_pub_key
        .y
        .fill(0);

    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_owner_ecc_sig_zero_signature_r() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    // Set owner_sig.r to zero.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.r.fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_owner_ecc_sig_zero_signature_s() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    // Set owner_sig.s to zero.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.s.fill(0);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_owner_ecc_sig_invalid_signature_r() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    // Set an invalid owner_sig.r.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.r.fill(1);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_header_verify_owner_ecc_sig_invalid_signature_s() {
    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let gen = ImageGenerator::new(OsslCrypto::default());
    let digest = gen
        .owner_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: digest,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    // Set an invalid owner_sig.s.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.s.fill(1);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_toc_invalid_entry_count() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Change the TOC length.
    image_bundle.manifest.header.toc_len = caliptra_image_types::MAX_TOC_ENTRY_COUNT + 1;
    update_header(&mut image_bundle);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_toc_invalid_toc_digest() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Change the TOC digest.
    image_bundle.manifest.header.toc_digest[0] = 0xDEADBEEF;
    update_header(&mut image_bundle);

    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH.into()),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_toc_fmc_size_zero() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let fmc_new_size = 0;
    // These are unchanged.
    let fmc_new_offset = image_bundle.manifest.fmc.offset;
    let runtime_new_offset = image_bundle.manifest.runtime.offset;
    let runtime_new_size = image_bundle.manifest.runtime.size;

    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );
    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO.into()),
        hw.upload_firmware(&image).unwrap_err()
    );
}

#[test]
fn test_toc_fmc_range_overlap() {
    // Case 1: FMC offset == Runtime offset
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let fmc_new_offset = image_bundle.manifest.runtime.offset;
    // These are unchanged.
    let fmc_new_size = image_bundle.manifest.fmc.size;
    let runtime_new_offset = image_bundle.manifest.runtime.offset;
    let runtime_new_size = image_bundle.manifest.runtime.size;

    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );
    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP.into()),
        hw.upload_firmware(&image).unwrap_err()
    );

    // Case 2: FMC offset > Runtime offset
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let fmc_new_offset = image_bundle.manifest.runtime.offset + 1;
    // These are unchanged.
    let fmc_new_size = image_bundle.manifest.fmc.size;
    let runtime_new_offset = image_bundle.manifest.runtime.offset;
    let runtime_new_size = image_bundle.manifest.runtime.size;
    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );

    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP.into()),
        hw.upload_firmware(&image).unwrap_err()
    );

    // // Case 3: FMC start offset < Runtime offset < FMC end offset
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let runtime_new_offset = image_bundle.manifest.fmc.offset + 1;
    // These are unchanged.
    let fmc_new_offset = image_bundle.manifest.fmc.offset;
    let fmc_new_size = image_bundle.manifest.fmc.size;
    let runtime_new_size = image_bundle.manifest.runtime.size;
    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );

    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP.into()),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_toc_fmc_range_incorrect_order() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let fmc_new_offset = image_bundle.manifest.runtime.offset;
    let fmc_new_size = image_bundle.manifest.runtime.size;
    let runtime_new_offset = image_bundle.manifest.fmc.offset;
    let runtime_new_size = image_bundle.manifest.fmc.size;

    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_rt_load_address_range_overlap() {
    // Case 1:
    // [-FMC--]
    //      [--RT--]
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let rt_new_load_addr = image_bundle.manifest.fmc.load_addr + 1;
    let image = update_load_addr(&mut image_bundle, false, rt_new_load_addr);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );

    // Case 2:
    //      [-FMC--]
    //  [--RT--]
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let fmc_new_load_addr = image_bundle.manifest.runtime.load_addr + 1;
    let image = update_load_addr(&mut image_bundle, true, fmc_new_load_addr);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_digest_mismatch() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Change the FMC image.
    image_bundle.fmc[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH.into()),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_invalid_load_addr_before_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_load_addr(&mut image_bundle, true, ICCM_ORG - 4);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_invalid_load_addr_after_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_load_addr(&mut image_bundle, true, ICCM_END_ADDR + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_not_contained_in_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_load_addr(&mut image_bundle, true, ICCM_END_ADDR - 4);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );
}

#[test]
fn test_fmc_load_addr_unaligned() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let load_addr = image_bundle.manifest.fmc.load_addr;
    let image = update_load_addr(&mut image_bundle, true, load_addr + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_invalid_entry_point_before_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_entry_point(&mut image_bundle, true, ICCM_ORG - 4);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_invalid_entry_point_after_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_entry_point(&mut image_bundle, true, ICCM_END_ADDR + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_entry_point_unaligned() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let entry_point = image_bundle.manifest.fmc.entry_point;

    let image = update_entry_point(&mut image_bundle, true, entry_point + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_svn_greater_than_32() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };

    let image_options = ImageOptions {
        fmc_svn: 33,
        ..Default::default()
    };

    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_svn_less_than_min_svn() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };

    let image_options = ImageOptions {
        fmc_min_svn: 3,
        fmc_svn: 2,
        ..Default::default()
    };
    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_fmc_svn_less_than_fuse_svn() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        fmc_key_manifest_svn: 0b11, // fuse svn = 2
        ..Default::default()
    };

    let image_options = ImageOptions {
        fmc_svn: 1,
        ..Default::default()
    };

    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_toc_rt_size_zero() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let runtime_new_size = 0;

    // These are unchanged.
    let fmc_new_size = image_bundle.manifest.fmc.size;
    let fmc_new_offset = image_bundle.manifest.fmc.offset;
    let runtime_new_offset = image_bundle.manifest.runtime.offset;

    let image = update_fmc_runtime_ranges(
        &mut image_bundle,
        fmc_new_offset,
        fmc_new_size,
        runtime_new_offset,
        runtime_new_size,
    );
    assert_eq!(
        ModelError::MailboxCmdFailed(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO.into()),
        hw.upload_firmware(&image).unwrap_err()
    );
}

#[test]
fn test_runtime_digest_mismatch() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    // Change the FMC image.
    image_bundle.runtime[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_invalid_load_addr_before_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let rt_new_load_addr = ICCM_ORG
        - (image_bundle.manifest.fmc.load_addr - ICCM_ORG + image_bundle.manifest.runtime.size);
    let image = update_load_addr(&mut image_bundle, false, rt_new_load_addr);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_invalid_load_addr_after_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_load_addr(&mut image_bundle, false, ICCM_END_ADDR + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_not_contained_in_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_load_addr(&mut image_bundle, false, ICCM_END_ADDR - 3);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );
}

#[test]
fn test_runtime_load_addr_unaligned() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let load_addr = image_bundle.manifest.runtime.load_addr;
    let image = update_load_addr(&mut image_bundle, false, load_addr + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_invalid_entry_point_before_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_entry_point(&mut image_bundle, false, ICCM_ORG - 4);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_invalid_entry_point_after_iccm() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());

    let image = update_entry_point(&mut image_bundle, false, ICCM_END_ADDR + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_entry_point_unaligned() {
    let (mut hw, mut image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let entry_point = image_bundle.manifest.runtime.entry_point;
    let image = update_entry_point(&mut image_bundle, false, entry_point + 1);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED.into()
        ),
        hw.upload_firmware(&image).unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_svn_greater_than_max() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };
    let image_options = ImageOptions {
        app_svn: caliptra_image_verify::MAX_RUNTIME_SVN + 1,
        ..Default::default()
    };

    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_svn_less_than_min_svn() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };
    let image_options = ImageOptions {
        app_min_svn: 3,
        app_svn: 2,
        ..Default::default()
    };

    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn test_runtime_svn_less_than_fuse_svn() {
    let gen = ImageGenerator::new(OsslCrypto::default());
    let (_hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(Fuses::default(), ImageOptions::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&image_bundle.manifest.preamble)
        .unwrap();

    let fuse_svn: [u32; 4] = [0xffff_ffff, 0x7fff_ffff, 0, 0]; // fuse svn = 63
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        runtime_svn: fuse_svn,
        ..Default::default()
    };
    let image_options = ImageOptions {
        app_svn: 62,
        ..Default::default()
    };

    let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE.into()
        ),
        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap_err()
    );
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE.into()
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        FwProcessorManifestLoadComplete.into()
    );
}

#[test]
fn cert_test_with_custom_dates() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    let mut opts = ImageOptions::default();

    opts.vendor_config
        .not_before
        .copy_from_slice("20250101000000Z".as_bytes());

    opts.vendor_config
        .not_after
        .copy_from_slice("20260101000000Z".as_bytes());

    let mut own_config = opts.owner_config.unwrap();

    own_config
        .not_before
        .copy_from_slice("20270101000000Z".as_bytes());
    own_config
        .not_after
        .copy_from_slice("20280101000000Z".as_bytes());

    opts.owner_config = Some(own_config);

    let image_bundle =
        caliptra_builder::build_and_sign_image(&TEST_FMC_WITH_UART, &APP_WITH_UART, opts).unwrap();

    let mut output = vec![];

    // Set gen_idev_id_csr to generate CSR.
    let flags = MfgFlags::GENERATE_IDEVID_CSR;
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| flags.bits());

    // Download the CSR from the mailbox.
    let _ = helpers::get_csr(&mut hw);

    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(0x1000_0001, &[]).unwrap();

    let result = hw.copy_output_until_exit_success(&mut output);
    assert!(result.is_ok());
    let output = String::from_utf8_lossy(&output);

    // Get the idevid cert.
    let idevid_cert = idevid_cert(&output);

    // Get the ldevid cert.
    let ldevid_cert = ldevid_cert(&idevid_cert, &output);

    let not_before: Asn1Time = Asn1Time::from_str("20270101000000Z").unwrap();
    let not_after: Asn1Time = Asn1Time::from_str("20280101000000Z").unwrap();

    // Get the fmclias cert.
    let cert = fmcalias_cert(&ldevid_cert, &output);
    assert!(cert.not_before() == not_before);
    assert!(cert.not_after() == not_after);
}

#[test]
fn cert_test() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        ..Default::default()
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut output = vec![];

    // Set gen_idev_id_csr to generate CSR.
    let flags = MfgFlags::GENERATE_IDEVID_CSR;
    hw.soc_ifc()
        .cptra_dbg_manuf_service_reg()
        .write(|_| flags.bits());

    // Download the CSR from the mailbox.
    let _ = helpers::get_csr(&mut hw);

    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(0x1000_0001, &[]).unwrap();

    let result = hw.copy_output_until_exit_success(&mut output);
    assert!(result.is_ok());
    let output = String::from_utf8_lossy(&output);

    // Get the idevid cert.
    let idevid_cert = idevid_cert(&output);

    // Get the ldevid cert.
    let ldevid_cert = ldevid_cert(&idevid_cert, &output);

    // Get the fmclias cert.
    fmcalias_cert(&ldevid_cert, &output);
}

fn update_header(image_bundle: &mut ImageBundle) {
    let opts = ImageOptions::default();
    let config = ImageGeneratorConfig {
        fmc: ElfExecutable::default(),
        runtime: ElfExecutable::default(),
        vendor_config: opts.vendor_config,
        owner_config: opts.owner_config,
    };

    let gen = ImageGenerator::new(OsslCrypto::default());
    let header_digest_vendor = gen
        .header_digest_vendor(&image_bundle.manifest.header)
        .unwrap();
    let header_digest_owner = gen
        .header_digest_owner(&image_bundle.manifest.header)
        .unwrap();

    image_bundle.manifest.preamble = gen
        .gen_preamble(
            &config,
            image_bundle.manifest.preamble.vendor_ecc_pub_key_idx,
            image_bundle.manifest.preamble.vendor_lms_pub_key_idx,
            &header_digest_vendor,
            &header_digest_owner,
        )
        .unwrap();
}

fn update_fmc_runtime_ranges(
    image_bundle: &mut ImageBundle,
    fmc_new_offset: u32,
    fmc_new_size: u32,
    runtime_new_offset: u32,
    runtime_new_size: u32,
) -> Vec<u8> {
    image_bundle.manifest.fmc.offset = fmc_new_offset;
    image_bundle.manifest.fmc.size = fmc_new_size;
    image_bundle.manifest.runtime.offset = runtime_new_offset;
    image_bundle.manifest.runtime.size = runtime_new_size;

    let gen = ImageGenerator::new(OsslCrypto::default());

    // Update TOC digest.
    image_bundle.manifest.header.toc_digest = gen
        .toc_digest(&image_bundle.manifest.fmc, &image_bundle.manifest.runtime)
        .unwrap();

    // Update Header.
    update_header(image_bundle);

    // Generate image bytes.
    generate_image_bytes(image_bundle)
}

fn update_load_addr(image_bundle: &mut ImageBundle, is_fmc: bool, new_load_addr: u32) -> Vec<u8> {
    if is_fmc {
        image_bundle.manifest.fmc.load_addr = new_load_addr;
    } else {
        image_bundle.manifest.runtime.load_addr = new_load_addr;
    }

    let gen = ImageGenerator::new(OsslCrypto::default());

    // Update TOC digest.
    image_bundle.manifest.header.toc_digest = gen
        .toc_digest(&image_bundle.manifest.fmc, &image_bundle.manifest.runtime)
        .unwrap();

    // Update Header.
    update_header(image_bundle);

    // Generate image bytes.
    generate_image_bytes(image_bundle)
}

fn update_entry_point(
    image_bundle: &mut ImageBundle,
    is_fmc: bool,
    new_entry_point: u32,
) -> Vec<u8> {
    if is_fmc {
        image_bundle.manifest.fmc.entry_point = new_entry_point;
    } else {
        image_bundle.manifest.runtime.entry_point = new_entry_point;
    }

    let gen = ImageGenerator::new(OsslCrypto::default());

    // Update TOC digest.
    image_bundle.manifest.header.toc_digest = gen
        .toc_digest(&image_bundle.manifest.fmc, &image_bundle.manifest.runtime)
        .unwrap();

    // Update Header.
    update_header(image_bundle);

    // Generate image bytes.
    generate_image_bytes(image_bundle)
}

fn generate_image_bytes(image_bundle: &mut ImageBundle) -> Vec<u8> {
    let mut image = vec![];
    image.extend_from_slice(image_bundle.manifest.as_bytes());
    image.extend_from_slice(&image_bundle.fmc);
    image.extend_from_slice(&image_bundle.runtime);
    image
}

fn generate_self_signed_cert() -> (X509, PKey<Private>) {
    let mut x509_name = openssl::x509::X509NameBuilder::new().unwrap();
    x509_name
        .append_entry_by_text("CN", "Caliptra Test")
        .unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = openssl::x509::X509::builder().unwrap();
    x509_builder.set_subject_name(&x509_name).unwrap();

    // Set serial number.
    let big_num = BigNum::from_u32(1).unwrap();
    let serial_number = Asn1Integer::from_bn(big_num.as_ref()).unwrap();
    x509_builder
        .set_serial_number(serial_number.as_ref())
        .unwrap();

    // Set validity.
    let not_valid_before = Asn1Time::days_from_now(0).unwrap();
    let not_valid_after = Asn1Time::days_from_now(30).unwrap();
    x509_builder
        .set_not_before(not_valid_before.as_ref())
        .unwrap();
    x509_builder
        .set_not_after(not_valid_after.as_ref())
        .unwrap();

    // Generate a pkey pair.
    let rsa = Rsa::generate(2048).unwrap();
    let pkey_pair = PKey::from_rsa(rsa).unwrap();

    // Set public key.
    x509_builder.set_pubkey(pkey_pair.as_ref()).unwrap();

    // Since this is a self-signed certificate, we need to set the name of the
    // issuer to the name of the subject.
    x509_builder.set_issuer_name(x509_name.as_ref()).unwrap();

    // Sign the certificate with the private key.
    let hash = MessageDigest::md5();
    x509_builder.sign(pkey_pair.as_ref(), hash).unwrap();

    // Get the cert.
    let cert = x509_builder.build();
    println!("{}", str::from_utf8(&cert.to_text().unwrap()).unwrap());
    (cert, pkey_pair)
}

fn idevid_cert(output: &str) -> X509 {
    // Get CSR
    let csr_str = helpers::get_data("[idev] CSR = ", output);
    let csr = hex::decode(csr_str).unwrap();

    // Verify the signature on the certificate is valid.
    let req: X509Req = X509Req::from_der(&csr).unwrap();
    println!(
        "CSR:\n {}",
        str::from_utf8(&req.to_text().unwrap()).unwrap()
    );
    assert!(req.verify(&req.public_key().unwrap()).unwrap());

    // Generate a self-signed CA cert and get the corresponding key-pair.
    let (ca_cert, ca_pkey_pair) = generate_self_signed_cert();

    //
    // Create the idevid certificate.
    //
    let mut x509_builder = openssl::x509::X509::builder().unwrap();

    // Set the Subject Name from the CSR.
    x509_builder.set_subject_name(req.subject_name()).unwrap();

    // Set the Issue Name from the CA cert.
    x509_builder.set_issuer_name(ca_cert.issuer_name()).unwrap();

    // Set serial number.
    let big_num = BigNum::from_u32(1).unwrap();
    let serial_number = Asn1Integer::from_bn(big_num.as_ref()).unwrap();
    x509_builder
        .set_serial_number(serial_number.as_ref())
        .unwrap();

    // Set public key from the CSR.
    x509_builder.set_pubkey(&req.public_key().unwrap()).unwrap();

    // Set cert validity.
    let not_valid_before = Asn1Time::days_from_now(0).unwrap();
    let not_valid_after = Asn1Time::days_from_now(1).unwrap();
    x509_builder
        .set_not_before(not_valid_before.as_ref())
        .unwrap();
    x509_builder
        .set_not_after(not_valid_after.as_ref())
        .unwrap();

    // Sign the cert with the CA's private key.
    x509_builder
        .sign(ca_pkey_pair.as_ref(), MessageDigest::md5())
        .unwrap();

    // Get the cert.
    let idevid_cert = x509_builder.build();
    println!(
        "IDEVID Cert from CSR:\n{}",
        str::from_utf8(&idevid_cert.to_text().unwrap()).unwrap()
    );
    idevid_cert
}

fn ldevid_cert(idevd_cert: &X509, output: &str) -> X509 {
    // Get the ldevid cert
    let ldevid_cert =
        X509::from_der(&hex::decode(helpers::get_data("[fmc] LDEVID cert = ", output)).unwrap())
            .unwrap();
    println!(
        "LDEVID Cert:\n{}",
        str::from_utf8(&ldevid_cert.to_text().unwrap()).unwrap()
    );

    // Get ldevid public key
    let pub_key_from_dv =
        hex::decode(helpers::get_data("[fmc] LDEVID PUBLIC KEY DER = ", output)).unwrap();

    // Verify the signature on the cert is valid.
    let pub_key_from_cert = ldevid_cert
        .public_key()
        .as_ref()
        .unwrap()
        .public_key_to_der()
        .unwrap();
    assert_eq!(pub_key_from_dv, pub_key_from_cert[23..]);

    // Verify the ldevid cert using idevid cert's public key.
    assert!(ldevid_cert
        .verify(idevd_cert.public_key().as_ref().unwrap())
        .unwrap());

    ldevid_cert
}

fn fmcalias_cert(ldevid_cert: &X509, output: &str) -> X509 {
    // Get the ldevid cert
    let fmcalias_cert =
        X509::from_der(&hex::decode(helpers::get_data("[fmc] FMCALIAS cert = ", output)).unwrap())
            .unwrap();
    println!(
        "FMCALIAS Cert:\n {}",
        str::from_utf8(&fmcalias_cert.to_text().unwrap()).unwrap()
    );

    // Get fmclias public key
    let pub_key_from_dv = hex::decode(helpers::get_data(
        "[fmc] FMCALIAS PUBLIC KEY DER = ",
        output,
    ))
    .unwrap();

    // Verify the signature on the cert is valid.
    let pub_key_from_cert = fmcalias_cert
        .public_key()
        .as_ref()
        .unwrap()
        .public_key_to_der()
        .unwrap();
    assert_eq!(pub_key_from_dv, pub_key_from_cert[23..]);

    // Verify the ldevid cert using idevid cert's public key.
    assert!(fmcalias_cert
        .verify(ldevid_cert.public_key().as_ref().unwrap())
        .unwrap());

    fmcalias_cert
}
