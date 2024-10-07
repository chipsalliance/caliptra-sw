// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{
        self,
        rom_tests::{
            FAKE_TEST_FMC_INTERACTIVE, FAKE_TEST_FMC_WITH_UART, TEST_FMC_INTERACTIVE,
            TEST_FMC_WITH_UART, TEST_RT_WITH_UART,
        },
        APP_WITH_UART,
    },
    FwId, ImageOptions,
};
use caliptra_common::mailbox_api::CommandId;
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::WarmResetEntry4;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0;
use caliptra_image_gen::ImageGeneratorVendorConfig;
use zerocopy::{AsBytes, FromBytes};

const TEST_FMC_CMD_RESET_FOR_UPDATE: u32 = 0x1000_0004;
const TEST_FMC_CMD_RESET_FOR_UPDATE_KEEP_MBOX_CMD: u32 = 0x1000_000B;

#[test]
fn test_update_reset_success() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
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

    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    // Exit test-fmc with success
    hw.mailbox_execute(0x1000_000C, &[]).unwrap();

    hw.step_until_exit_success().unwrap();
}

#[test]
fn test_update_reset_no_mailbox_cmd() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // This command tells the test-fmc to do an update reset after clearing
    // itself from the mailbox.
    hw.mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE, &[])
        .unwrap();

    hw.step_until_boot_status(KatStarted.into(), true);
    hw.step_until_boot_status(KatComplete.into(), true);
    hw.step_until_boot_status(UpdateResetStarted.into(), false);

    // No command in the mailbox.
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_non_fatal().read() != 0);
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE)
    );

    let _ = hw.mailbox_execute(0xDEADBEEF, &[]);
    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        u32::from(UpdateResetStarted)
    );
}

#[test]
fn test_update_reset_non_fw_load_cmd() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // This command tells the test-fmc to do an update reset but leave the
    // "unknown" command in the mailbox for the ROM to find
    hw.start_mailbox_execute(TEST_FMC_CMD_RESET_FOR_UPDATE_KEEP_MBOX_CMD, &[])
        .unwrap();
    hw.step_until_boot_status(KatStarted.into(), true);
    hw.step_until_boot_status(KatComplete.into(), true);
    hw.step_until_boot_status(UpdateResetStarted.into(), true);

    let _ = hw.mailbox_execute(0xDEADBEEF, &[]);
    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND)
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        u32::from(UpdateResetStarted)
    );
}

#[test]
fn test_update_reset_verify_image_failure() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Upload invalid manifest
    hw.start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &[0u8; 4])
        .unwrap();

    hw.step_until_boot_status(KatStarted.into(), true);
    hw.step_until_boot_status(KatComplete.into(), true);
    hw.step_until_boot_status(UpdateResetStarted.into(), false);

    assert_eq!(
        hw.finish_mailbox_execute(),
        Err(caliptra_hw_model::ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH.into()
        ))
    );

    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH)
    );

    assert_eq!(
        hw.soc_ifc().cptra_boot_status().read(),
        u32::from(UpdateResetLoadManifestComplete)
    );
}

#[test]
fn test_update_reset_boot_status() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Start the firmware update process
    hw.start_mailbox_execute(
        CommandId::FIRMWARE_LOAD.into(),
        &image_bundle.to_bytes().unwrap(),
    )
    .unwrap();

    if cfg!(not(feature = "fpga_realtime")) {
        hw.step_until_boot_status(CfiInitialized.into(), false);
        hw.step_until_boot_status(KatStarted.into(), false);
        hw.step_until_boot_status(KatComplete.into(), false);
        hw.step_until_boot_status(UpdateResetStarted.into(), false);
        hw.step_until_boot_status(UpdateResetLoadManifestComplete.into(), false);
        hw.step_until_boot_status(UpdateResetImageVerificationComplete.into(), false);
        hw.step_until_boot_status(UpdateResetPopulateDataVaultComplete.into(), false);
        hw.step_until_boot_status(UpdateResetExtendPcrComplete.into(), false);
        hw.step_until_boot_status(UpdateResetLoadImageComplete.into(), false);
        hw.step_until_boot_status(UpdateResetOverwriteManifestComplete.into(), false);
        hw.step_until_boot_status(UpdateResetComplete.into(), false);
    }

    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    assert_eq!(hw.finish_mailbox_execute(), Ok(None));

    // Tell the test-fmc to "exit with success" (necessary because the FMC is in
    // interactive mode)
    hw.mailbox_execute(0x1000_000C, &[]).unwrap();

    hw.step_until_exit_success().unwrap();
}

#[test]
fn test_update_reset_vendor_ecc_pub_key_idx_dv_mismatch() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let vendor_config_cold_boot = ImageGeneratorVendorConfig {
        ecc_key_idx: 3,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options = ImageOptions {
        vendor_config: vendor_config_cold_boot,
        ..Default::default()
    };
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        image_options,
    )
    .unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Upload firmware with a different vendor ECC key index.
    let vendor_config_update_reset = ImageGeneratorVendorConfig {
        ecc_key_idx: 2,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options = ImageOptions {
        vendor_config: vendor_config_update_reset,
        ..Default::default()
    };

    let image_bundle =
        caliptra_builder::build_and_sign_image(&TEST_FMC_WITH_UART, &APP_WITH_UART, image_options)
            .unwrap();

    hw.start_mailbox_execute(
        CommandId::FIRMWARE_LOAD.into(),
        &image_bundle.to_bytes().unwrap(),
    )
    .unwrap();

    hw.step_until_boot_status(UpdateResetStarted.into(), true);

    assert_eq!(
        hw.finish_mailbox_execute(),
        Err(caliptra_hw_model::ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH.into()
        ))
    );

    // Exit test-fmc with success
    hw.mailbox_execute(0x1000_000C, &[]).unwrap();

    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH)
    );
}

#[test]
fn test_update_reset_vendor_lms_pub_key_idx_dv_mismatch() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let vendor_config_cold_boot = ImageGeneratorVendorConfig {
        lms_key_idx: 3,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options = ImageOptions {
        vendor_config: vendor_config_cold_boot,
        ..Default::default()
    };
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        image_options,
    )
    .unwrap();

    // Generate firmware with a different vendor LMS key index.
    let vendor_config_update_reset = ImageGeneratorVendorConfig {
        lms_key_idx: 2,
        ..VENDOR_CONFIG_KEY_0
    };
    let image_options = ImageOptions {
        vendor_config: vendor_config_update_reset,
        ..Default::default()
    };
    let image_bundle2 = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        image_options,
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fuses: caliptra_hw_model::Fuses {
                lms_verify: true,
                ..Default::default()
            },
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    assert_eq!(
        hw.upload_firmware(&image_bundle2.to_bytes().unwrap()),
        Err(caliptra_hw_model::ModelError::MailboxCmdFailed(
            CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_LMS_PUB_KEY_IDX_MISMATCH.into()
        ))
    );

    // Exit test-fmc with success
    hw.mailbox_execute(0x1000_000C, &[]).unwrap();

    hw.step_until_exit_success().unwrap();

    assert_eq!(
        hw.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_LMS_PUB_KEY_IDX_MISMATCH)
    );
}

#[test]
fn test_check_rom_update_reset_status_reg() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
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

    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    let warmresetentry4_array = hw.mailbox_execute(0x1000_000D, &[]).unwrap().unwrap();
    let mut warmresetentry4_offset = core::mem::size_of::<u32>() * 8; // Skip first four entries

    // Check RomUpdateResetStatus datavault value.
    let warmresetentry4_id =
        u32::read_from_prefix(warmresetentry4_array[warmresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(
        warmresetentry4_id,
        WarmResetEntry4::RomUpdateResetStatus as u32
    );
    warmresetentry4_offset += core::mem::size_of::<u32>();
    let warmresetentry4_value =
        u32::read_from_prefix(warmresetentry4_array[warmresetentry4_offset..].as_bytes()).unwrap();
    assert_eq!(warmresetentry4_value, u32::from(UpdateResetComplete));
}

#[test]
fn test_fmc_is_16k() {
    struct Fmc<'a> {
        name: &'a str,
        fwid: &'a FwId<'static>,
    }

    let errs: String = [
        Fmc {
            name: "TEST_FMC_INTERACTIVE",
            fwid: &TEST_FMC_INTERACTIVE,
        },
        Fmc {
            name: "FAKE_TEST_FMC_WITH_UART",
            fwid: &FAKE_TEST_FMC_WITH_UART,
        },
        Fmc {
            name: "FAKE_TEST_FMC_INTERACTIVE",
            fwid: &FAKE_TEST_FMC_INTERACTIVE,
        },
    ]
    .map(|fmc| -> String {
        let bundle = caliptra_builder::build_and_sign_image(
            fmc.fwid,
            &TEST_RT_WITH_UART,
            ImageOptions::default(),
        )
        .unwrap();

        let fmc_size = bundle.fmc.len();
        let delta = 16 * 1024 - fmc_size as isize;
        if delta != 0 {
            format!(
                "Adjust PAD_LEN in rom/dev/tools/test-fmc/src/main.rs by {} for {}",
                delta, fmc.name
            )
        } else {
            String::from("")
        }
    })
    .into_iter()
    .filter(|err| !err.is_empty())
    .collect::<Vec<String>>()
    .join("\n");

    println!("{}", errs);
    assert!(errs.is_empty());
}

#[test]
fn test_update_reset_max_fw_image() {
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image_bundle.to_bytes().unwrap()),
            ..Default::default()
        },
    )
    .unwrap();

    hw.step_until_boot_status(ColdResetComplete.into(), true);

    // Trigger an update reset with new firmware
    let updated_image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_INTERACTIVE,
        &TEST_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let image_bytes = updated_image_bundle.to_bytes().unwrap();

    // Sanity-check that the image is 128k
    assert_eq!(
        128 * 1024 - image_bytes.len() as isize,
        0,
        "Try adjusting PAD_LEN in rom/dev/tools/test-fmc/src/main.rs"
    );

    hw.start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &image_bytes)
        .unwrap();

    if cfg!(not(feature = "fpga_realtime")) {
        hw.step_until_boot_status(KatStarted.into(), true);
        hw.step_until_boot_status(KatComplete.into(), true);
        hw.step_until_boot_status(UpdateResetStarted.into(), false);
    }

    assert_eq!(hw.finish_mailbox_execute(), Ok(None));

    hw.step_until_boot_status(UpdateResetComplete.into(), true);

    let mut buf = vec![];
    buf.append(
        &mut updated_image_bundle
            .manifest
            .fmc
            .image_size()
            .to_le_bytes()
            .to_vec(),
    );
    buf.append(
        &mut updated_image_bundle
            .manifest
            .runtime
            .image_size()
            .to_le_bytes()
            .to_vec(),
    );
    buf.append(&mut updated_image_bundle.fmc.to_vec());
    buf.append(&mut updated_image_bundle.runtime.to_vec());

    let iccm_cmp: Vec<u8> = hw.mailbox_execute(0x1000_000E, &buf).unwrap().unwrap();
    assert_eq!(iccm_cmp.len(), 1);
    assert_eq!(iccm_cmp[0], 0);
}
