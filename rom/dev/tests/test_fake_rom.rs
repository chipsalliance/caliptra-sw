// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{rom_tests::FAKE_TEST_FMC_WITH_UART, APP_WITH_UART, ROM_FAKE_WITH_UART},
    ImageOptions,
};
use caliptra_common::{mailbox_api::CommandId, RomBootStatus::*};
use caliptra_drivers::{Array4x12, CaliptraError};
use caliptra_hw_model::{
    BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, ModelError, SecurityState,
};

pub mod helpers;

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

#[test]
fn test_skip_kats() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // If KatStarted boot status is posted before ColResetStarted, the statement below will trigger panic.
    hw.step_until_boot_status(
        caliptra_common::RomBootStatus::ColdResetStarted.into(),
        false,
    );
}

#[test]
fn test_fake_rom_production_error() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // Let it run until a fatal error (should fail very early)
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Make sure we see the right fatal error
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        CaliptraError::ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION.into()
    );
}

#[test]
fn test_fake_rom_fw_load() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
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

    // Build the image we are going to send to ROM to load
    let image_bundle = caliptra_builder::build_and_sign_image(
        &FAKE_TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    // Upload the FW once ROM is at the right point
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    // Keep going until we launch FMC
    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    // Make sure we actually get into FMC
    hw.step_until_output_contains("Running Caliptra FMC")
        .unwrap();
}

#[test]
fn test_fake_rom_update_reset() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
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
        &FAKE_TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    // Upload FW
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Upload FW again
    hw.start_mailbox_execute(
        CommandId::FIRMWARE_LOAD.into(),
        &image_bundle.to_bytes().unwrap(),
    )
    .unwrap();

    hw.step_until_boot_status(UpdateResetStarted.into(), true);

    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    assert_eq!(hw.finish_mailbox_execute(), Ok(None));

    hw.step_until_exit_success().unwrap();
}

#[test]
fn test_image_verify() {
    const DBG_MANUF_FAKE_ROM_IMAGE_VERIFY: u32 = 0x1 << 31; // BIT 31 turns on image verify
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAKE_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            security_state: SecurityState::from(fuses.life_cycle as u32),
            ..Default::default()
        },
        fuses,
        initial_dbg_manuf_service_reg: DBG_MANUF_FAKE_ROM_IMAGE_VERIFY,
        ..Default::default()
    })
    .unwrap();

    let mut image_bundle = caliptra_builder::build_and_sign_image(
        &FAKE_TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let vendor_ecc_pub_key_idx = image_bundle.manifest.preamble.vendor_ecc_pub_key_idx as usize;

    // Modify the vendor public key.
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
}
