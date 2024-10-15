// Licensed under the Apache-2.0 license
use crate::common;

use caliptra_builder::firmware::{
    APP_WITH_UART, FMC_FAKE_WITH_UART, FMC_WITH_UART, ROM_WITH_FIPS_TEST_HOOKS,
};
use caliptra_builder::ImageOptions;
use caliptra_common::memory_layout::{ICCM_ORG, ICCM_SIZE};
use caliptra_drivers::CaliptraError;
use caliptra_drivers::FipsTestHook;
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, ModelError, SecurityState, U4,
};
use caliptra_image_crypto::OsslCrypto as Crypto;
use caliptra_image_fake_keys::{VENDOR_CONFIG_KEY_0, VENDOR_CONFIG_KEY_1};
use caliptra_image_gen::{ImageGenerator, ImageGeneratorConfig, ImageGeneratorVendorConfig};
use caliptra_image_types::SHA384_DIGEST_WORD_SIZE;
use caliptra_image_types::{
    FwImageType, ImageBundle, VENDOR_ECC_MAX_KEY_COUNT, VENDOR_LMS_MAX_KEY_COUNT,
};
use openssl::sha::{sha384, Sha384};

use common::*;
use zerocopy::AsBytes;

#[allow(dead_code)]
#[derive(PartialEq, Eq)]
enum HdrDigest {
    Update,
    Skip,
}

#[derive(PartialEq, Eq)]
enum TocDigest {
    Update,
    Skip,
}

pub fn build_fw_image(image_options: ImageOptions) -> ImageBundle {
    caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &APP_WITH_UART, image_options).unwrap()
}

fn update_manifest(image_bundle: &mut ImageBundle, hdr_digest: HdrDigest, toc_digest: TocDigest) {
    let opts = ImageOptions::default();
    let config = ImageGeneratorConfig {
        fmc: caliptra_image_elf::ElfExecutable::default(),
        runtime: caliptra_image_elf::ElfExecutable::default(),
        vendor_config: opts.vendor_config,
        owner_config: opts.owner_config,
        fw_image_type: FwImageType::EccLms,
    };

    let gen = ImageGenerator::new(Crypto::default());

    // Update TOC digest
    if toc_digest == TocDigest::Update {
        image_bundle.manifest.header.toc_digest = gen
            .toc_digest(&image_bundle.manifest.fmc, &image_bundle.manifest.runtime)
            .unwrap();
    }

    if hdr_digest == HdrDigest::Update {
        let header_digest_vendor = gen
            .header_digest_vendor(&image_bundle.manifest.header)
            .unwrap();
        let header_digest_owner = gen
            .header_digest_owner(&image_bundle.manifest.header)
            .unwrap();

        // Update preamble
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
}

// Get a byte array from an image_bundle without any error checking
// Normally, to_bytes will perform some error checking
// We need to bypass this for the sake of these tests
fn image_to_bytes_no_error_check(image_bundle: &ImageBundle) -> Vec<u8> {
    let mut image = vec![];
    image.extend_from_slice(image_bundle.manifest.as_bytes());
    image.extend_from_slice(&image_bundle.fmc);
    image.extend_from_slice(&image_bundle.runtime);
    image
}

// Returns a fuse struct with safe values for boot
// (Mainly needed for manufacturing or production security states)
fn safe_fuses(fw_image: &ImageBundle) -> Fuses {
    let gen = ImageGenerator::new(Crypto::default());

    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();

    let owner_pubkey_digest = gen
        .owner_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();

    Fuses {
        key_manifest_pk_hash: vendor_pubkey_digest,
        owner_pk_hash: owner_pubkey_digest,
        ..Default::default()
    }
}

// NOTE: These tests are about the image verification which is contained in ROM.
//       The version of the FW used in the image bundles within these tests is irrelevant.
//       Because of this, we are just building the FW so it's easier to modify components
//       of the image bundle instead of using any pre-existing FW binary

fn fw_load_error_flow(fw_image: Option<ImageBundle>, fuses: Option<Fuses>, exp_error_code: u32) {
    fw_load_error_flow_base(fw_image, None, fuses, None, exp_error_code, None);
}

fn fw_load_error_flow_with_test_hooks(
    fw_image: Option<ImageBundle>,
    fuses: Option<Fuses>,
    exp_error_code: u32,
    test_hook_cmd: u8,
) {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();
    fw_load_error_flow_base(
        fw_image,
        Some(&rom),
        fuses,
        None,
        exp_error_code,
        Some((test_hook_cmd as u32) << HOOK_CODE_OFFSET),
    );
}

fn update_fw_error_flow(
    fw_image: Option<ImageBundle>,
    fuses: Option<Fuses>,
    update_fw_image: Option<ImageBundle>,
    exp_error_code: u32,
) {
    let update_fw_image = update_fw_image.unwrap_or(build_fw_image(ImageOptions::default()));

    fw_load_error_flow_base(
        fw_image,
        None,
        fuses,
        Some(update_fw_image),
        exp_error_code,
        None,
    );
}

fn fw_load_error_flow_base(
    fw_image: Option<ImageBundle>,
    rom: Option<&[u8]>,
    fuses: Option<Fuses>,
    update_fw_image: Option<ImageBundle>,
    exp_error_code: u32,
    initial_dbg_manuf_service_reg: Option<u32>,
) {
    // Use defaults if not provided
    let fuses = fuses.unwrap_or(Fuses::default());
    let fw_image = fw_image.unwrap_or(build_fw_image(ImageOptions::default()));

    // Attempt to load the FW
    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            security_state: SecurityState::from(fuses.life_cycle as u32),
            rom: rom.unwrap_or_default(),
            ..Default::default()
        }),
        Some(BootParams {
            fuses,
            initial_dbg_manuf_service_reg: initial_dbg_manuf_service_reg.unwrap_or_default(),
            ..Default::default()
        }),
    );

    // Upload initial FW
    let mut fw_load_result = hw.upload_firmware(&image_to_bytes_no_error_check(&fw_image));

    // Update the FW if specified
    match update_fw_image {
        None => {
            // Verify the correct error was returned from FW load
            assert_eq!(
                ModelError::MailboxCmdFailed(exp_error_code),
                fw_load_result.unwrap_err()
            );

            // Verify we cannot utilize RT FW by sending a message
            verify_mbox_cmds_fail(&mut hw, exp_error_code);

            // Verify an undocumented attempt to clear the error fails
            hw.soc_ifc().cptra_fw_error_fatal().write(|_| 0);
            hw.soc_ifc().cptra_fw_error_non_fatal().write(|_| 0);
            verify_mbox_cmds_fail(&mut hw, 0);

            // Clear the error with an approved method - restart Caliptra
            // TODO: Reset to the default fuse state - provided fuses may be intended to cause errors
            if cfg!(any(feature = "verilator", feature = "fpga_realtime")) {
                hw.cold_reset();
            } else {
                hw = fips_test_init_model(None)
            }

            let clean_fw_image = build_fw_image(ImageOptions::default());

            hw.boot(BootParams {
                fuses: safe_fuses(&clean_fw_image),
                ..Default::default()
            })
            .unwrap();

            hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

            // Verify we can load FW (use clean FW)
            hw.upload_firmware(&clean_fw_image.to_bytes().unwrap())
                .unwrap();
        }
        Some(update_image) => {
            // Verify initial FW load was successful
            fw_load_result.unwrap();

            // Update FW
            fw_load_result = hw.upload_firmware(&image_to_bytes_no_error_check(&update_image));
            // Verify the correct error was returned from FW load
            assert_eq!(
                fw_load_result.unwrap_err(),
                ModelError::MailboxCmdFailed(exp_error_code)
            );

            // In the update FW case, the error will be non-fatal and fall back to the previous, good FW

            // Verify we can load FW (use first FW)
            hw.upload_firmware(&image_to_bytes_no_error_check(&fw_image))
                .unwrap();
        }
    }
}

#[test]
fn fw_load_error_manifest_marker_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Corrupt manifest marker
    fw_image.manifest.marker = 0xDEADBEEF;

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_manifest_size_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change manifest size
    fw_image.manifest.size -= 1;

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_vendor_pub_key_digest_invalid() {
    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0u32; 12],
        ..Default::default()
    };

    fw_load_error_flow(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_vendor_pub_key_digest_failure() {
    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    fw_load_error_flow_with_test_hooks(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into(),
        FipsTestHook::FW_LOAD_VENDOR_PUB_KEY_DIGEST_FAILURE,
    );
}

#[test]
fn fw_load_error_vendor_pub_key_digest_mismatch() {
    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        key_manifest_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    fw_load_error_flow(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_owner_pub_key_digest_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE.into(),
        FipsTestHook::FW_LOAD_OWNER_PUB_KEY_DIGEST_FAILURE,
    );
}

#[test]
fn fw_load_error_owner_pub_key_digest_mismatch() {
    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        owner_pk_hash: [0xDEADBEEF; 12],
        ..Default::default()
    };

    fw_load_error_flow(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_vendor_ecc_pub_key_index_out_of_bounds() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change ECC pub key index to max+1
    fw_image.manifest.preamble.vendor_ecc_pub_key_idx = VENDOR_ECC_MAX_KEY_COUNT;

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS.into(),
    );
}

#[test]
fn fw_load_error_vendor_ecc_pub_key_revoked() {
    let vendor_config = VENDOR_CONFIG_KEY_1;
    let image_options = ImageOptions {
        vendor_config,
        ..Default::default()
    };

    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        key_manifest_pk_hash_mask: U4::try_from(1u32 << image_options.vendor_config.ecc_key_idx)
            .unwrap(),
        ..Default::default()
    };

    // Generate image
    let fw_image = build_fw_image(image_options);

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_header_digest_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE.into(),
        FipsTestHook::FW_LOAD_HEADER_DIGEST_FAILURE,
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_vendor_ecc_verify_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE.into(),
        FipsTestHook::FW_LOAD_VENDOR_ECC_VERIFY_FAILURE,
    );
}

#[test]
fn fw_load_error_vendor_ecc_signature_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Corrupt vendor ECC sig
    fw_image.manifest.preamble.vendor_sigs.ecc_sig.r.fill(1);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID.into(),
    );
}

#[test]
fn fw_load_error_vendor_ecc_pub_key_index_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change vendor pubkey index.
    fw_image.manifest.header.vendor_ecc_pub_key_idx =
        fw_image.manifest.preamble.vendor_ecc_pub_key_idx + 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_owner_ecc_verify_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE.into(),
        FipsTestHook::FW_LOAD_OWNER_ECC_VERIFY_FAILURE,
    );
}

#[test]
fn fw_load_error_owner_ecc_signature_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Corrupt owner ECC sig
    fw_image.manifest.preamble.owner_sigs.ecc_sig.r.fill(1);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID.into(),
    );
}

#[test]
fn fw_load_error_toc_entry_count_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change the TOC length to over the maximum
    fw_image.manifest.header.toc_len = caliptra_image_types::MAX_TOC_ENTRY_COUNT + 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_toc_digest_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURE.into(),
        FipsTestHook::FW_LOAD_OWNER_TOC_DIGEST_FAILURE,
    );
}

#[test]
fn fw_load_error_toc_digest_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change the TOC digest.
    fw_image.manifest.header.toc_digest[0] = 0xDEADBEEF;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Skip);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_fmc_digest_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE.into(),
        FipsTestHook::FW_LOAD_FMC_DIGEST_FAILURE,
    );
}

#[test]
fn fw_load_error_fmc_digest_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change the FMC image.
    fw_image.fmc[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_runtime_digest_failure() {
    fw_load_error_flow_with_test_hooks(
        None,
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE.into(),
        FipsTestHook::FW_LOAD_RUNTIME_DIGEST_FAILURE,
    );
}

#[test]
fn fw_load_error_runtime_digest_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change the runtime image.
    fw_image.runtime[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_fmc_runtime_overlap() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Corrupt FMC offset
    fw_image.manifest.fmc.offset = fw_image.manifest.runtime.offset;

    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP.into(),
    );
}

#[test]
fn fw_load_error_fmc_runtime_incorrect_order() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Flip FMC and RT positions
    let old_fmc_offset = fw_image.manifest.fmc.offset;
    let old_fmc_size = fw_image.manifest.fmc.size;
    fw_image.manifest.fmc.offset = fw_image.manifest.runtime.offset;
    fw_image.manifest.fmc.size = fw_image.manifest.runtime.size;
    fw_image.manifest.runtime.offset = old_fmc_offset;
    fw_image.manifest.runtime.size = old_fmc_size;

    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER.into(),
    );
}

#[test]
fn fw_load_error_owner_ecc_pub_key_invalid_arg() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Set ecc_pub_key.y to zero.
    fw_image
        .manifest
        .preamble
        .owner_pub_keys
        .ecc_pub_key
        .y
        .fill(0);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG.into(),
    );
}

#[test]
fn fw_load_error_owner_ecc_signature_invalid_arg() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Set owner_sig.s to zero.
    fw_image.manifest.preamble.owner_sigs.ecc_sig.s.fill(0);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG.into(),
    );
}

#[test]
fn fw_load_error_vendor_pub_key_digest_invalid_arg() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Set ecc_pub_key.x to zero.
    fw_image
        .manifest
        .preamble
        .vendor_ecc_active_pub_key
        .x
        .fill(0);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG.into(),
    );
}

#[test]
fn fw_load_error_vendor_ecc_signature_invalid_arg() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Set vendor_sig.r to zero.
    fw_image.manifest.preamble.vendor_sigs.ecc_sig.r.fill(0);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG.into(),
    );
}

#[test]
fn fw_load_error_update_reset_owner_digest_failure() {
    // Generate image
    let mut update_image = build_fw_image(ImageOptions::default());

    // Set ecc_pub_key.y to some corrupted, non-zero value
    update_image
        .manifest
        .preamble
        .owner_pub_keys
        .ecc_pub_key
        .y
        .fill(0x1234abcd);

    update_fw_error_flow(
        None,
        None,
        Some(update_image),
        CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE.into(),
    );
}

#[test]
fn fw_load_error_update_reset_vendor_ecc_pub_key_idx_mismatch() {
    let vendor_config_cold_boot = ImageGeneratorVendorConfig {
        ecc_key_idx: 3,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options_cold_boot = ImageOptions {
        vendor_config: vendor_config_cold_boot,
        ..Default::default()
    };
    let vendor_config_update_reset = ImageGeneratorVendorConfig {
        ecc_key_idx: 2,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options_update_reset = ImageOptions {
        vendor_config: vendor_config_update_reset,
        ..Default::default()
    };
    // Generate images
    let first_image = build_fw_image(image_options_cold_boot);
    let update_image = build_fw_image(image_options_update_reset);

    update_fw_error_flow(
        Some(first_image),
        None,
        Some(update_image),
        CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_update_reset_fmc_digest_mismatch() {
    // Generate images
    let first_image = build_fw_image(ImageOptions::default());
    // Use a different FMC for the update image
    let update_image = caliptra_builder::build_and_sign_image(
        &FMC_FAKE_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    update_fw_error_flow(
        Some(first_image),
        None,
        Some(update_image),
        CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_fmc_load_addr_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC load addr
    fw_image.manifest.fmc.load_addr = ICCM_ORG - 4;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID.into(),
    );
}

#[test]
fn fw_load_error_fmc_load_addr_unaligned() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC load addr
    fw_image.manifest.fmc.load_addr += 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED.into(),
    );
}

#[test]
fn fw_load_error_fmc_entry_point_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC entry point
    fw_image.manifest.fmc.entry_point = ICCM_ORG - 4;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID.into(),
    );
}

#[test]
fn fw_load_error_fmc_entry_point_unaligned() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC entry point
    fw_image.manifest.fmc.entry_point += 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED.into(),
    );
}

#[test]
fn fw_load_error_fmc_svn_greater_than_max_supported() {
    // Generate image
    let image_options = ImageOptions {
        fmc_svn: 33,
        ..Default::default()
    };
    let fw_image = build_fw_image(image_options);

    // Set fuses
    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED.into(),
    );
}

// IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED is defined but never used in the code (svn is a u32)

#[test]
fn fw_load_error_fmc_svn_less_than_fuse() {
    // Generate image
    let image_options = ImageOptions {
        fmc_svn: 1,
        ..Default::default()
    };
    let fw_image = build_fw_image(image_options);

    // Set fuses
    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        fmc_key_manifest_svn: 0b11, // fuse svn = 2
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE.into(),
    );
}

#[test]
fn fw_load_error_runtime_load_addr_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime load addr
    fw_image.manifest.runtime.load_addr = ICCM_ORG + ICCM_SIZE;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID.into(),
    );
}

#[test]
fn fw_load_error_runtime_load_addr_unaligned() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime load addr
    fw_image.manifest.runtime.load_addr += 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED.into(),
    );
}

#[test]
fn fw_load_error_runtime_entry_point_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime entry point
    fw_image.manifest.runtime.entry_point = ICCM_ORG - 4;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID.into(),
    );
}

#[test]
fn fw_load_error_runtime_entry_point_unaligned() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime entry point
    fw_image.manifest.runtime.entry_point += 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED.into(),
    );
}

#[test]
fn fw_load_error_runtime_svn_greater_than_max_supported() {
    // Generate image
    let image_options = ImageOptions {
        app_svn: caliptra_image_verify::MAX_RUNTIME_SVN + 1,
        ..Default::default()
    };
    let fw_image = build_fw_image(image_options);

    // Set fuses
    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED.into(),
    );
}

// IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED is defined but never used in the code (svn is a u32)

#[test]
fn fw_load_error_runtime_svn_less_than_fuse() {
    // Generate image
    let image_options = ImageOptions {
        app_svn: 62,
        ..Default::default()
    };
    let fw_image = build_fw_image(image_options);

    // Set fuses
    let gen = ImageGenerator::new(Crypto::default());
    let vendor_pubkey_digest = gen
        .vendor_pubkey_digest(&fw_image.manifest.preamble)
        .unwrap();
    let fuses = caliptra_hw_model::Fuses {
        life_cycle: DeviceLifecycle::Manufacturing,
        anti_rollback_disable: false,
        key_manifest_pk_hash: vendor_pubkey_digest,
        runtime_svn: [0xffff_ffff, 0x7fff_ffff, 0, 0], // fuse svn = 63
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE.into(),
    );
}

#[test]
fn fw_load_error_image_len_more_than_bundle_size() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime size to exceed bundle
    fw_image.manifest.runtime.size += 4;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE.into(),
    );
}

#[test]
fn fw_load_error_vendor_lms_pub_key_index_mismatch() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change vendor pubkey index.
    fw_image.manifest.header.vendor_lms_pub_key_idx =
        fw_image.manifest.preamble.vendor_lms_pub_key_idx + 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_vendor_lms_verify_failure() {
    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow_with_test_hooks(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE.into(),
        FipsTestHook::FW_LOAD_VENDOR_LMS_VERIFY_FAILURE,
    );
}

#[test]
fn fw_load_error_vendor_lms_pub_key_index_out_of_bounds() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Set LMS pub key index to MAX + 1
    fw_image.manifest.preamble.vendor_lms_pub_key_idx = VENDOR_LMS_MAX_KEY_COUNT;

    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_OUT_OF_BOUNDS.into(),
    );
}

#[test]
fn fw_load_error_vendor_lms_signature_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Modify the vendor public key.
    fw_image.manifest.preamble.vendor_lms_active_pub_key.digest = [Default::default(); 6];

    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID.into(),
    );
}

#[test]
fn fw_load_error_fmc_runtime_load_addr_overlap() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime entry point
    fw_image.manifest.runtime.load_addr = fw_image.manifest.fmc.load_addr + 1;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP.into(),
    );
}

#[test]
#[cfg(not(feature = "test_env_immutable_rom"))]
fn fw_load_error_owner_lms_verify_failure() {
    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow_with_test_hooks(
        None,
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_VERIFY_FAILURE.into(),
        FipsTestHook::FW_LOAD_OWNER_LMS_VERIFY_FAILURE,
    );
}

#[test]
fn fw_load_error_owner_lms_signature_invalid() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Modify the owner public key
    fw_image.manifest.preamble.owner_pub_keys.lms_pub_key.digest = [Default::default(); 6];

    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID.into(),
    );
}

#[test]
fn fw_load_error_vendor_lms_pub_key_revoked() {
    let vendor_config = ImageGeneratorVendorConfig {
        lms_key_idx: 5,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options = ImageOptions {
        vendor_config,
        ..Default::default()
    };

    // Set fuses
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        fuse_lms_revocation: 1u32 << image_options.vendor_config.lms_key_idx,
        ..Default::default()
    };

    // Generate image
    let fw_image = build_fw_image(image_options);

    fw_load_error_flow(
        Some(fw_image),
        Some(fuses),
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED.into(),
    );
}

#[test]
fn fw_load_error_fmc_size_zero() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC size to 0
    fw_image.manifest.fmc.size = 0;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO.into(),
    );
}

#[test]
fn fw_load_error_runtime_size_zero() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime size to 0
    fw_image.manifest.runtime.size = 0;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO.into(),
    );
}

#[test]
fn fw_load_error_update_reset_vendor_lms_pub_key_idx_mismatch() {
    let vendor_config_update_reset = ImageGeneratorVendorConfig {
        lms_key_idx: 2,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options_update_reset = ImageOptions {
        vendor_config: vendor_config_update_reset,
        ..Default::default()
    };
    // Generate image
    let update_image = build_fw_image(image_options_update_reset);

    // Turn LMS verify on
    let fuses = caliptra_hw_model::Fuses {
        lms_verify: true,
        ..Default::default()
    };

    update_fw_error_flow(
        None,
        Some(fuses),
        Some(update_image),
        CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_LMS_PUB_KEY_IDX_MISMATCH.into(),
    );
}

#[test]
fn fw_load_error_fmc_load_address_image_size_arithmetic_overflow() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change FMC load addr to cause overflow
    fw_image.manifest.fmc.load_addr = 0xFFFFFFF0;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW.into(),
    );
}

#[test]
fn fw_load_error_runtime_load_address_image_size_arithmetic_overflow() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change runtime load addr to cause overflow
    fw_image.manifest.runtime.load_addr = 0xFFFFFFF0;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW
            .into(),
    );
}

#[test]
fn fw_load_error_toc_entry_range_arithmetic_overflow() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change fmc offset to cause overflow
    fw_image.manifest.fmc.offset = 0xFFFFFFF0;
    update_manifest(&mut fw_image, HdrDigest::Update, TocDigest::Update);

    fw_load_error_flow(
        Some(fw_image),
        None,
        CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_RANGE_ARITHMETIC_OVERFLOW.into(),
    );
}

// IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS is not possible if there is no SW bug
// IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE or an ARITHMETIC_OVERFLOW error would catch this first

fn fw_load_bad_pub_key_flow(fw_image: ImageBundle, exp_error_code: u32) {
    // Generate pub key hashes and set fuses
    // Use a fresh image (will NOT be loaded)
    let pk_hash_src_image = build_fw_image(ImageOptions::default());
    let owner_pk_hash = sha384(
        pk_hash_src_image
            .manifest
            .preamble
            .owner_pub_keys
            .as_bytes(),
    );

    let mut hash_ctx = Sha384::new();
    let vendor_pub_key_info = &pk_hash_src_image.manifest.preamble.vendor_pub_key_info;
    hash_ctx.update(vendor_pub_key_info.ecc_key_descriptor.as_bytes());
    hash_ctx.update(
        (&vendor_pub_key_info.ecc_pub_key_hashes)
            [..vendor_pub_key_info.ecc_key_descriptor.key_hash_count as usize]
            .as_bytes(),
    );
    hash_ctx.update(vendor_pub_key_info.lms_key_descriptor.as_bytes());
    hash_ctx.update(
        (&vendor_pub_key_info.lms_pub_key_hashes)
            [..vendor_pub_key_info.lms_key_descriptor.key_hash_count as usize]
            .as_bytes(),
    );
    let vendor_pk_hash = &hash_ctx.finish();
    let vendor_pk_hash_words = bytes_to_be_words_48(vendor_pk_hash);

    let owner_pk_hash_words = bytes_to_be_words_48(&owner_pk_hash);

    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Production,
        key_manifest_pk_hash: vendor_pk_hash_words,
        owner_pk_hash: owner_pk_hash_words,
        lms_verify: true,
        ..Default::default()
    };

    // Load the FW
    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        }),
        Some(BootParams {
            fuses,
            ..Default::default()
        }),
    );
    let fw_load_result = hw.upload_firmware(&image_to_bytes_no_error_check(&fw_image));

    // Make sure we got the right error
    assert_eq!(
        ModelError::MailboxCmdFailed(exp_error_code),
        fw_load_result.unwrap_err()
    );
}

#[test]
fn fw_load_bad_vendor_ecc_pub_key() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());

    // Modify the pub key
    fw_image
        .manifest
        .preamble
        .vendor_pub_key_info
        .ecc_pub_key_hashes[0][0] ^= 0x1;

    fw_load_bad_pub_key_flow(
        fw_image,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_bad_owner_ecc_pub_key() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());

    // Modify the pub key
    fw_image.manifest.preamble.owner_pub_keys.ecc_pub_key.x[0] ^= 0x1;

    fw_load_bad_pub_key_flow(
        fw_image,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_bad_vendor_lms_pub_key() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());

    // Modify the pub key
    fw_image
        .manifest
        .preamble
        .vendor_pub_key_info
        .lms_pub_key_hashes[0][0] ^= 0x1;

    fw_load_bad_pub_key_flow(
        fw_image,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_bad_owner_lms_pub_key() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());

    // Modify the pub key
    fw_image.manifest.preamble.owner_pub_keys.lms_pub_key.digest[0] = 0xDEADBEEF.into();

    fw_load_bad_pub_key_flow(
        fw_image,
        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_blank_pub_keys() {
    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());

    // Clear all pub keys
    fw_image
        .manifest
        .preamble
        .vendor_pub_key_info
        .ecc_pub_key_hashes = [[0u32; SHA384_DIGEST_WORD_SIZE]; VENDOR_ECC_MAX_KEY_COUNT as usize];
    fw_image.manifest.preamble.owner_pub_keys = caliptra_image_types::ImageOwnerPubKeys::default();

    fw_load_bad_pub_key_flow(
        fw_image,
        CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH.into(),
    );
}

#[test]
fn fw_load_blank_pub_key_hashes() {
    // Generate image
    let fw_image = build_fw_image(ImageOptions::default());

    // Don't populate pub key hashes
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Production,
        ..Default::default()
    };

    // Load the FW
    let mut hw = fips_test_init_to_rom(
        Some(InitParams {
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        }),
        Some(BootParams {
            fuses,
            ..Default::default()
        }),
    );
    let fw_load_result = hw.upload_firmware(&image_to_bytes_no_error_check(&fw_image));

    // Make sure we got the right error
    assert_eq!(
        ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID.into()
        ),
        fw_load_result.unwrap_err()
    );
}

#[test]
pub fn corrupted_fw_load_version() {
    let mut hw = fips_test_init_to_rom(None, None);

    // Generate image
    let mut fw_image = build_fw_image(ImageOptions::default());
    // Change the runtime image.
    fw_image.runtime[0..4].copy_from_slice(0xDEADBEEFu32.as_bytes());

    // Get the initial version
    // Normally we would use a command for this, but we cannot issue commands after a fatal error
    // from a failed FW load. We will use the version/rev reg directly instead. (This is the source
    // for the response of the version command)
    let rom_fmc_fw_version_before = hw.soc_ifc().cptra_fw_rev_id().read();

    // Load the FW
    let fw_load_result = hw.upload_firmware(&image_to_bytes_no_error_check(&fw_image));

    // Make sure we got the right error
    let exp_err: u32 = CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH.into();
    assert_eq!(
        ModelError::MailboxCmdFailed(exp_err),
        fw_load_result.unwrap_err()
    );

    // Make sure we can't use the module
    verify_mbox_cmds_fail(&mut hw, exp_err);

    // Verify version info is unchanged
    assert_eq!(
        rom_fmc_fw_version_before,
        hw.soc_ifc().cptra_fw_rev_id().read()
    );
}
