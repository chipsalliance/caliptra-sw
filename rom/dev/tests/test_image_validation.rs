// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_drivers::Array4x12;
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, ModelEmulated, SecurityState, U4,
};
use caliptra_image_elf::ElfExecutable;
use caliptra_image_fake_keys::{
    VENDOR_CONFIG_KEY_0, VENDOR_CONFIG_KEY_1, VENDOR_CONFIG_KEY_2, VENDOR_CONFIG_KEY_3,
};
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig, ImageGeneratorVendorConfig};
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::{ImageBundle, ImageManifest, VENDOR_ECC_KEY_COUNT};
use zerocopy::AsBytes;

// [TODO] Use the error codes from the common library.
const MANIFEST_MARKER_MISMATCH: u32 = 0x0B000001;
const MANIFEST_SIZE_MISMATCH: u32 = 0x0B000002;
const VENDOR_PUB_KEY_DIGEST_INVALID: u32 = 0x0B000003;
const VENDOR_PUB_KEY_DIGEST_INVALID_ARG: u32 = 0x0B00001B;
const VENDOR_ECC_SIGNATURE_INVALID_ARG: u32 = 0x0B00001C;
const VENDOR_ECC_SIGNATURE_INVALID: u32 = 0x0B00000C;
const OWNER_ECC_SIGNATURE_INVALID_ARG: u32 = 0x0B00001A;
const TOC_ENTRY_COUNT_INVALID: u32 = 0x0B000010;
const TOC_DIGEST_MISMATCH: u32 = 0x0B000012;
const FMC_RUNTIME_OVERLAP: u32 = 0x0B000017;
const FMC_RUNTIME_INCORRECT_ORDER: u32 = 0x0B000018;
const FMC_DIGEST_MISMATCH: u32 = 0x0B000014;
const RUNTIME_DIGEST_MISMATCH: u32 = 0x0B000016;
const OWNER_PUB_KEY_DIGEST_INVALID_ARG: u32 = 0x0B000019;
const OWNER_PUB_KEY_DIGEST_MISMATCH: u32 = 0x0B000007;
const VENDOR_PUB_KEY_DIGEST_MISMATCH: u32 = 0x0B000005;
const VENDOR_ECC_PUB_KEY_REVOKED: u32 = 0x0B000009;
const VENDOR_ECC_PUB_KEY_INDEX_MISMATCH: u32 = 0x0B00000D;
const VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS: u32 = 0x0B000008;

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
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    image_bundle.manifest.marker = 0xDEADBEEF;
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let mut output = vec![];
    let result = hw.copy_output_until_non_fatal_error(MANIFEST_MARKER_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_invalid_manifest_size() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    image_bundle.manifest.size = (core::mem::size_of::<ImageManifest>() - 1) as u32;
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let mut output = vec![];
    let result = hw.copy_output_until_non_fatal_error(MANIFEST_SIZE_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_preamble_zero_vendor_pubkey_digest() {
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0u32; 12],
        ..Default::default()
    };
    let (mut hw, image_bundle) = build_hw_model_and_image_bundle(fuses);
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let mut output = vec![];
    let result = hw.copy_output_until_non_fatal_error(VENDOR_PUB_KEY_DIGEST_INVALID, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_preamble_vendor_pubkey_digest_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    let (mut hw, image_bundle) = build_hw_model_and_image_bundle(fuses);
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let mut output = vec![];
    let result = hw.copy_output_until_non_fatal_error(VENDOR_PUB_KEY_DIGEST_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_preamble_owner_pubkey_digest_mismatch() {
    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    let (mut hw, image_bundle) = build_hw_model_and_image_bundle(fuses);
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let mut output = vec![];
    let result = hw.copy_output_until_non_fatal_error(OWNER_PUB_KEY_DIGEST_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_preamble_vendor_pubkey_revocation() {
    let mut output = vec![];
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
            fw_image: None,
        })
        .unwrap();

        let image_bundle =
            caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options)
                .unwrap();

        hw.upload_firmware(&image_bundle.to_bytes().unwrap())
            .unwrap();

        let result = if key_idx == LAST_KEY_IDX {
            // Last key is never revoked.
            hw.copy_output_until_exit_success(&mut output)
        } else {
            hw.copy_output_until_non_fatal_error(VENDOR_ECC_PUB_KEY_REVOKED, &mut output)
        };

        assert!(result.is_ok());
    }
}

#[test]
fn test_preamble_vendor_pubkey_out_of_bounds() {
    let mut output = vec![];
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    image_bundle.manifest.preamble.vendor_ecc_pub_key_idx = VENDOR_ECC_KEY_COUNT;
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS, &mut output);

    assert!(result.is_ok());
}

#[test]
fn test_header_verify_vendor_sig_zero_pubkey() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let vendor_ecc_pub_key_idx = image_bundle.manifest.preamble.vendor_ecc_pub_key_idx as usize;
    let mut output = vec![];

    // Set ecc_pub_key.x to zero.
    let ecc_pub_key_x_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx].x;
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .x
        .fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_PUB_KEY_DIGEST_INVALID_ARG, &mut output);
    assert!(result.is_ok());

    // Set ecc_pub_key.y to zero.
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx].x =
        ecc_pub_key_x_backup;
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .y
        .fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_PUB_KEY_DIGEST_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_vendor_sig_zero_signature() {
    let mut output = vec![];
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());

    // Set vendor_sig.r to zero.
    let vendor_sig_r_backup = image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r;
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r.fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_ECC_SIGNATURE_INVALID_ARG, &mut output);
    assert!(result.is_ok());

    // Set vendor_sig.s to zero.
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.r = vendor_sig_r_backup;
    image_bundle.manifest.preamble.vendor_sigs.ecc_sig.s.fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_ECC_SIGNATURE_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_vendor_sig_mismatch() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let vendor_ecc_pub_key_idx = image_bundle.manifest.preamble.vendor_ecc_pub_key_idx as usize;
    let mut output = vec![];

    // Modify the owner public key.
    let ecc_pub_key_backup =
        image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx];

    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .x
        .clone_from_slice(Array4x12::from(PUB_KEY_X).0.as_slice());
    image_bundle.manifest.preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx]
        .y
        .clone_from_slice(Array4x12::from(PUB_KEY_Y).0.as_slice());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(VENDOR_ECC_SIGNATURE_INVALID, &mut output);
    assert!(result.is_ok());

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

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(VENDOR_ECC_SIGNATURE_INVALID, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_vendor_pub_key_in_preamble_and_header() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Change vendor pubkey index.
    image_bundle.manifest.header.vendor_ecc_pub_key_idx =
        image_bundle.manifest.preamble.vendor_ecc_pub_key_idx + 1;
    update_header(&mut image_bundle);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result =
        hw.copy_output_until_non_fatal_error(VENDOR_ECC_PUB_KEY_INDEX_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_owner_sig_zero_pubkey_x() {
    let mut output = vec![];

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
        fw_image: None,
    })
    .unwrap();

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result =
        hw.copy_output_until_non_fatal_error(OWNER_PUB_KEY_DIGEST_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_owner_sig_zero_pubkey_y() {
    let mut output = vec![];

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
        fw_image: None,
    })
    .unwrap();

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result =
        hw.copy_output_until_non_fatal_error(OWNER_PUB_KEY_DIGEST_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_owner_sig_zero_signature_r() {
    let mut output = vec![];

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
        fw_image: None,
    })
    .unwrap();

    // Set owner_sig.r to zero.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.r.fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result = hw.copy_output_until_non_fatal_error(OWNER_ECC_SIGNATURE_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_header_verify_owner_sig_zero_signature_s() {
    let mut output = vec![];

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
        fw_image: None,
    })
    .unwrap();

    // Set owner_sig.s to zero.
    image_bundle.manifest.preamble.owner_sigs.ecc_sig.s.fill(0);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    let result = hw.copy_output_until_non_fatal_error(OWNER_ECC_SIGNATURE_INVALID_ARG, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_toc_invalid_entry_count() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Change the TOC length.
    image_bundle.manifest.header.toc_len = caliptra_image_types::MAX_TOC_ENTRY_COUNT + 1;
    update_header(&mut image_bundle);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(TOC_ENTRY_COUNT_INVALID, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_toc_invalid_toc_digest() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Change the TOC digest.
    image_bundle.manifest.header.toc_digest[0] = 0xDEADBEEF;
    update_header(&mut image_bundle);

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(TOC_DIGEST_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_toc_fmc_range_overlap() {
    let mut output = vec![];

    // Case 1: FMC offset == Runtime offset
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
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
    hw.upload_firmware(&image).unwrap();
    let result = hw.copy_output_until_non_fatal_error(FMC_RUNTIME_OVERLAP, &mut output);
    assert!(result.is_ok());

    // Case 2: FMC offset > Runtime offset
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
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
    hw.upload_firmware(&image).unwrap();
    let result = hw.copy_output_until_non_fatal_error(FMC_RUNTIME_OVERLAP, &mut output);
    assert!(result.is_ok());

    // // Case 3: FMC start offset < Runtime offset < FMC end offset
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
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
    hw.upload_firmware(&image).unwrap();
    let result = hw.copy_output_until_non_fatal_error(FMC_RUNTIME_OVERLAP, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_toc_fmc_range_incorrect_order() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];
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
    hw.upload_firmware(&image).unwrap();
    let result = hw.copy_output_until_non_fatal_error(FMC_RUNTIME_INCORRECT_ORDER, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_fmc_digest_mismatch() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Change the FMC image.
    image_bundle.fmc[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(FMC_DIGEST_MISMATCH, &mut output);
    assert!(result.is_ok());
}

#[test]
fn test_runtime_digest_mismatch() {
    let (mut hw, mut image_bundle) = build_hw_model_and_image_bundle(Fuses::default());
    let mut output = vec![];

    // Change the FMC image.
    image_bundle.runtime[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();
    let result = hw.copy_output_until_non_fatal_error(RUNTIME_DIGEST_MISMATCH, &mut output);
    assert!(result.is_ok());
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
    let digest = gen.header_digest(&image_bundle.manifest.header).unwrap();
    image_bundle.manifest.preamble = gen
        .gen_preamble(
            &config,
            image_bundle.manifest.preamble.vendor_ecc_pub_key_idx,
            &digest,
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
    let mut image = vec![];
    image.extend_from_slice(image_bundle.manifest.as_bytes());
    image.extend_from_slice(&image_bundle.fmc);
    image.extend_from_slice(&image_bundle.runtime);
    image
}

fn build_hw_model_and_image_bundle(fuses: Fuses) -> (ModelEmulated, ImageBundle) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        fw_image: None,
    })
    .unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    (hw, image_bundle)
}
