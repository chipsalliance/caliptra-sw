// Licensed under the Apache-2.0 license

use caliptra_builder::ROM_VAL_WITH_UART;
use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART};
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{BootParams, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState};

pub mod helpers;

const TEST_FMC_CMD_RESET_FOR_UPDATE: u32 = 0x1000_0004;

const VAL_TEST_FMC_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom-test-fmc",
    bin_name: "caliptra-rom-test-fmc",
    features: &["emu", "val-fmc"],
    workspace_dir: None,
};

#[test]
fn test_skip_kats() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_VAL_WITH_UART).unwrap();
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
fn test_val_rom_production_error() {
    let security_state =
        *SecurityState::default().set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_VAL_WITH_UART).unwrap();
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
        CaliptraError::ROM_GLOBAL_VAL_ROM_IN_PRODUCTION.into()
    );
}

#[test]
fn test_val_rom_fw_load() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_VAL_WITH_UART).unwrap();
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
        &VAL_TEST_FMC_WITH_UART,
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
fn test_val_rom_update_reset() {
    let fuses = Fuses::default();
    let rom = caliptra_builder::build_firmware_rom(&ROM_VAL_WITH_UART).unwrap();
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
        &VAL_TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    // Upload FW
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Send command to test FMC to initiate a reset for update
    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_boot_status(UpdateResetStarted.into(), true);

    // Upload FW again
    hw.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());
    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_boot_status(UpdateResetComplete.into(), true);
    hw.step_until_exit_success().unwrap();
}
