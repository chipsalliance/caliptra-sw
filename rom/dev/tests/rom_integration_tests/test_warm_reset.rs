// Licensed under the Apache-2.0 license

use caliptra_builder::firmware::FMC_WITH_UART;
use caliptra_builder::firmware::{APP_WITH_UART, ROM_WITH_UART};
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::DeviceLifecycle;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
use caliptra_test::swap_word_bytes_inplace;
use openssl::sha::sha384;
use openssl::sha::Sha384;
use zerocopy::AsBytes;

use crate::helpers;

fn bytes_to_be_words_48(buf: &[u8; 48]) -> [u32; 12] {
    let mut result: [u32; 12] = zerocopy::transmute!(*buf);
    swap_word_bytes_inplace(&mut result);
    result
}

#[test]
fn test_warm_reset_success() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let mut hash_ctx = Sha384::new();
    let vendor_pub_key_info = &image.manifest.preamble.vendor_pub_key_info;
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
    let vendor_pk_hash = bytes_to_be_words_48(&hash_ctx.finish());

    let owner_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.owner_pub_keys.as_bytes()));

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                key_manifest_pk_hash: vendor_pk_hash,
                owner_pk_hash,
                fmc_key_manifest_svn: 0b1111111,
                ..Default::default()
            },
            fw_image: Some(&image.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    // Perform warm reset
    hw.warm_reset_flow(&Fuses {
        key_manifest_pk_hash: vendor_pk_hash,
        owner_pk_hash,
        fmc_key_manifest_svn: 0b1111111,
        ..Default::default()
    });

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }
}

#[test]
fn test_warm_reset_during_cold_boot_before_image_validation() {
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Production,
        ..Default::default()
    };

    let (mut hw, _image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    // Step till Cold boot starts
    hw.step_until_boot_status(IDevIdDecryptUdsComplete.into(), true);

    // Perform a warm reset
    hw.warm_reset_flow(&Fuses::default());

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
    );
}

#[test]
fn test_warm_reset_during_cold_boot_during_image_validation() {
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Unprovisioned,
        ..Default::default()
    };

    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    hw.start_mailbox_execute(
        CommandId::FIRMWARE_LOAD.into(),
        &image_bundle.to_bytes().unwrap(),
    )
    .unwrap();

    hw.step_until_boot_status(FwProcessorManifestLoadComplete.into(), true);

    // Step for few times to land in image validation
    for _ in 0..1000 {
        hw.step();
    }

    // Perform a warm reset
    hw.warm_reset_flow(&Fuses::default());

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
    );
}

#[test]
fn test_warm_reset_during_cold_boot_after_image_validation() {
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Unprovisioned,
        ..Default::default()
    };

    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    // Step till after last step in cold boot is complete
    hw.step_until_boot_status(FmcAliasDerivationComplete.into(), true);

    // Perform a warm reset
    hw.warm_reset_flow(&Fuses::default());

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET)
    );
}

#[test]
fn test_warm_reset_during_update_reset() {
    let fuses = Fuses {
        life_cycle: DeviceLifecycle::Unprovisioned,
        ..Default::default()
    };

    let (mut hw, image_bundle) =
        helpers::build_hw_model_and_image_bundle(fuses, ImageOptions::default());

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Trigger an update reset with "new" firmware
    hw.start_mailbox_execute(
        CommandId::FIRMWARE_LOAD.into(),
        &image_bundle.to_bytes().unwrap(),
    )
    .unwrap();

    if cfg!(not(feature = "fpga_realtime")) {
        hw.step_until_boot_status(KatStarted.into(), true);
        hw.step_until_boot_status(KatComplete.into(), true);
        hw.step_until_boot_status(UpdateResetStarted.into(), false);
    }

    assert_eq!(hw.finish_mailbox_execute(), Ok(None));

    // Step till after last step in update reset is complete
    hw.step_until_boot_status(UpdateResetLoadImageComplete.into(), true);

    // Perform a warm reset
    hw.warm_reset_flow(&Fuses::default());

    // Wait for error
    while hw.soc_ifc().cptra_fw_error_fatal().read() == 0 {
        hw.step();
    }
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET)
    );
}
