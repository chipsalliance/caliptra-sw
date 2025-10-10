// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{FipsVersionResp, MailboxReqHeader, MailboxRespHeader},
    SocManager,
};
use caliptra_builder::{
    firmware::{APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART},
    version, ImageOptions,
};
use caliptra_common::{fips::FipsVersionCmd, mailbox_api::CommandId, RomBootStatus::*};
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
};
use caliptra_test::swap_word_bytes_inplace;
use openssl::sha::sha384;
use zerocopy::{FromBytes, IntoBytes};

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
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.vendor_pub_keys.as_bytes()));
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

const HW_REV_ID: u32 = if cfg!(feature = "hw-1.0") { 0x1 } else { 0x11 };

fn test_version(
    hw: &mut DefaultHwModel,
    hw_rev: u32,
    rom_version: u32,
    fmc_version: u32,
    app_version: u32,
) {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::VERSION), &[]),
    };

    let response = hw
        .mailbox_execute(CommandId::VERSION.into(), payload.as_bytes())
        .unwrap()
        .unwrap();

    let version_resp = FipsVersionResp::ref_from_bytes(response.as_bytes()).unwrap();

    // Verify response checksum
    assert!(caliptra_common::checksum::verify_checksum(
        version_resp.hdr.chksum,
        0x0,
        &version_resp.as_bytes()[core::mem::size_of_val(&version_resp.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        version_resp.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    // Verify Version Info
    assert_eq!(version_resp.mode, FipsVersionCmd::MODE);

    // fips_rev[0] is hw_rev_id
    // fips_rev[1] is FMC version at 31:16 and ROM version at 15:0
    // fips_rev[2] is app (fw) version
    let received_hw_rev = version_resp.fips_rev[0];
    let received_rom_version = version_resp.fips_rev[1] & 0x0000FFFF;
    let received_fmc_version = (version_resp.fips_rev[1] & 0xFFFF0000) >> 16;
    let received_app_version = version_resp.fips_rev[2];

    assert_eq!(received_hw_rev, hw_rev);
    assert_eq!(received_rom_version, rom_version);
    assert_eq!(received_fmc_version, fmc_version);
    assert_eq!(received_app_version, app_version);
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

#[test]
fn test_warm_reset_version() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let fmc_version = 3;
    let app_version = 5;

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fmc_version,
            app_version,
            fmc_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();
    let vendor_pk_hash =
        bytes_to_be_words_48(&sha384(image.manifest.preamble.vendor_pub_keys.as_bytes()));
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

    test_version(
        &mut hw,
        HW_REV_ID,
        version::get_rom_version().into(),
        fmc_version.into(),
        app_version,
    );

    // Perform warm reset
    hw.warm_reset_flow(&Fuses::default());

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    test_version(
        &mut hw,
        HW_REV_ID,
        version::get_rom_version().into(),
        fmc_version.into(),
        app_version,
    );
}
