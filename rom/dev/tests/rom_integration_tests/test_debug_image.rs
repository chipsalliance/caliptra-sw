// Licensed under the Apache-2.0 license

use crate::helpers;
use crate::test_derive_stable_key::HW_MODEL_MODES_SUBSYSTEM;
use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{
        rom_tests::{TEST_FMC_INTERACTIVE, TEST_FMC_WITH_UART},
        APP_WITH_UART_FPGA,
    },
    ImageOptions,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::*;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams};
use caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0;
use caliptra_image_gen::ImageGeneratorVendorConfig;

fn debug_image_options(pqc_key_type: caliptra_image_types::FwVerificationPqcKeyType) -> ImageOptions {
    let vendor_config = ImageGeneratorVendorConfig {
        debug_image: true,
        ..VENDOR_CONFIG_KEY_0
    };
    ImageOptions {
        pqc_key_type,
        vendor_config,
        ..Default::default()
    }
}

#[test]
fn test_debug_image_cold_reset_rejected_without_debug_intent() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let image_options = debug_image_options(*pqc_key_type);
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
            let image_bundle = caliptra_builder::build_and_sign_image(
                &TEST_FMC_WITH_UART,
                &APP_WITH_UART_FPGA,
                image_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses,
                    rom: &rom,
                    subsystem_mode,
                    debug_intent: false,
                    ..Default::default()
                },
                BootParams::default(),
            )
            .unwrap();

            helpers::assert_fatal_fw_load(
                &mut hw,
                *pqc_key_type,
                &image_bundle.to_bytes().unwrap(),
                CaliptraError::IMAGE_VERIFIER_ERR_DEBUG_IMAGE_NOT_ALLOWED,
            );
        }
    }
}

#[test]
fn test_debug_image_cold_reset_accepted_with_debug_intent() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        // Debug Intent is a subsystem strap; skip passive-only configurations.
        if !subsystem_mode {
            continue;
        }
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let image_options = debug_image_options(*pqc_key_type);
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
            let image_bundle = caliptra_builder::build_and_sign_image(
                &TEST_FMC_WITH_UART,
                &APP_WITH_UART_FPGA,
                image_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses,
                    rom: &rom,
                    subsystem_mode,
                    debug_intent: true,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image_bundle.to_bytes().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(ColdResetComplete.into(), true);
            hw.step_until_exit_success().unwrap();
        }
    }
}

#[test]
fn test_non_debug_image_cold_reset_with_debug_intent() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        if !subsystem_mode {
            continue;
        }
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let image_options = ImageOptions {
                pqc_key_type: *pqc_key_type,
                ..Default::default()
            };
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
            let image_bundle = caliptra_builder::build_and_sign_image(
                &TEST_FMC_WITH_UART,
                &APP_WITH_UART_FPGA,
                image_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses,
                    rom: &rom,
                    subsystem_mode,
                    debug_intent: true,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image_bundle.to_bytes().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(ColdResetComplete.into(), true);
            hw.step_until_exit_success().unwrap();
        }
    }
}

#[test]
fn test_debug_image_update_reset_rejected_without_debug_intent() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let cold_boot_options = ImageOptions {
                pqc_key_type: *pqc_key_type,
                ..Default::default()
            };
            let update_options = debug_image_options(*pqc_key_type);
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
            let cold_image = caliptra_builder::build_and_sign_image(
                &TEST_FMC_WITH_UART,
                &APP_WITH_UART_FPGA,
                cold_boot_options,
            )
            .unwrap();
            let debug_image = caliptra_builder::build_and_sign_image(
                &TEST_FMC_WITH_UART,
                &APP_WITH_UART_FPGA,
                update_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses,
                    rom: &rom,
                    subsystem_mode,
                    debug_intent: false,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&cold_image.to_bytes().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(ColdResetComplete.into(), true);

            hw.start_mailbox_execute(
                CommandId::FIRMWARE_LOAD.into(),
                &debug_image.to_bytes().unwrap(),
            )
            .unwrap();

            if cfg!(not(any(
                feature = "fpga_realtime",
                feature = "fpga_subsystem"
            ))) {
                hw.step_until_boot_status(KatStarted.into(), true);
                hw.step_until_boot_status(KatComplete.into(), true);
            }
            hw.step_until(|model| {
                model.soc_ifc().cptra_boot_status().read() >= u32::from(UpdateResetStarted)
            });

            assert_eq!(
                hw.finish_mailbox_execute(),
                Err(caliptra_hw_model::ModelError::MailboxCmdFailed(
                    CaliptraError::IMAGE_VERIFIER_ERR_DEBUG_IMAGE_NOT_ALLOWED.into()
                ))
            );

            assert_eq!(
                hw.soc_ifc().cptra_fw_error_non_fatal().read(),
                u32::from(CaliptraError::IMAGE_VERIFIER_ERR_DEBUG_IMAGE_NOT_ALLOWED)
            );
        }
    }
}

#[test]
fn test_debug_image_update_reset_accepted_with_debug_intent() {
    for &subsystem_mode in &HW_MODEL_MODES_SUBSYSTEM {
        if !subsystem_mode {
            continue;
        }
        for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
            let image_options = debug_image_options(*pqc_key_type);
            let fuses = Fuses {
                fuse_pqc_key_type: *pqc_key_type as u32,
                ..Default::default()
            };
            let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
            let image_bundle = caliptra_builder::build_and_sign_image(
                &TEST_FMC_INTERACTIVE,
                &APP_WITH_UART_FPGA,
                image_options,
            )
            .unwrap();

            let mut hw = caliptra_hw_model::new(
                InitParams {
                    fuses,
                    rom: &rom,
                    subsystem_mode,
                    debug_intent: true,
                    ..Default::default()
                },
                BootParams {
                    fw_image: Some(&image_bundle.to_bytes().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();

            hw.step_until_boot_status(ColdResetComplete.into(), true);

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
            hw.step_until_boot_status(UpdateResetComplete.into(), true);

            hw.mailbox_execute(0x1000_000C, &[]).unwrap();
            hw.step_until_exit_success().unwrap();
        }
    }
}
