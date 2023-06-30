// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, ROM_WITH_UART};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, SecurityState};
pub mod helpers;

const TEST_FMC_CMD_RESET_FOR_UPDATE: u32 = 0x1000_0004;

#[test]
fn test_update_reset_success() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

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

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_output_contains("[update-reset] ++").unwrap();

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_exit_success().unwrap();
}

#[test]
fn test_update_reset_no_mailbox_cmd() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

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

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_output_contains("[update-reset] ++").unwrap();

    // No command in the mailbox.
    hw.soc_mbox().cmd().write(|_| 0);
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_non_fatal().read() != 0);

    let _ = hw.mailbox_execute(0xDEADBEEF, &[]);
    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE.into()
    );
}

#[test]
fn test_update_reset_non_fw_load_cmd() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

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

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_output_contains("[update-reset] ++").unwrap();

    // Send a non-fw load command
    let _ = hw.mailbox_execute(0xDEADBEEF, &[]);
    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        CaliptraError::ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND.into()
    );
}

#[test]
fn test_update_reset_verify_image_failure() {
    pub const TEST_FMC_WITH_UART: FwId = FwId {
        crate_name: "caliptra-rom-test-fmc",
        bin_name: "caliptra-rom-test-fmc",
        features: &["emu"],
        workspace_dir: None,
    };

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

    hw.upload_firmware(&image_bundle.to_bytes().unwrap())
        .unwrap();

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_output_contains("[update-reset] ++").unwrap();

    // Upload invalid manifest
    let _ = hw.upload_firmware(&[0u8; 4]);

    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH.into()
    );
}
