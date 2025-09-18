// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::FMC_WITH_UART;
use caliptra_builder::firmware::{APP_WITH_UART, ROM_WITH_UART};
use caliptra_builder::{version, ImageOptions};
use caliptra_common::fips::FipsVersionCmd;
use caliptra_common::mailbox_api::{
    CommandId, FipsVersionResp, MailboxReqHeader, MailboxRespHeader,
};
use caliptra_common::RomBootStatus::*;
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::DeviceLifecycle;
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams, SecurityState};
use caliptra_test::image_pk_desc_hash;
use zerocopy::{FromBytes, IntoBytes};

use crate::helpers;

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
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
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
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        fw_svn: [0x7F, 0, 0, 0], // Equals 7
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
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

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
}

#[test]
fn test_warm_reset_during_cold_boot_after_image_validation() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

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
}

#[test]
fn test_warm_reset_during_update_reset() {
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            life_cycle: DeviceLifecycle::Unprovisioned,
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };

        let (mut hw, image_bundle) = helpers::build_hw_model_and_image_bundle(fuses, image_options);

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
}

const HW_REV_ID: u32 = 0x102;

fn test_version(hw: &mut DefaultHwModel) {
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
    // fw_rev[0] is FMC version at 31:16 and ROM version at 15:0
    // fw_rev[1] is app (fw) version
    // FMC and FW version are expected to be 0x0 before FW load
    assert_eq!(
        version_resp.fips_rev,
        [HW_REV_ID, (version::get_rom_version() as u32), 0x0]
    );
    let name = &version_resp.name[..];
    assert_eq!(name, FipsVersionCmd::NAME.as_bytes());
}

#[test]
fn test_warm_reset_version() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions {
            fw_svn: 9,
            ..Default::default()
        },
    )
    .unwrap();

    let (vendor_pk_desc_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state,
            ..Default::default()
        },
        BootParams {
            fuses: Fuses {
                vendor_pk_hash: vendor_pk_desc_hash,
                owner_pk_hash,
                fw_svn: [0x7F, 0, 0, 0], // Equals 7
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

    test_version(&mut hw);

    // Perform warm reset
    hw.warm_reset_flow(&Fuses {
        vendor_pk_hash: vendor_pk_desc_hash,
        owner_pk_hash,
        fw_svn: [0x7F, 0, 0, 0], // Equals 7
        ..Default::default()
    });

    // Wait for boot
    while !hw.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
        hw.step();
    }

    test_version(&mut hw);
}
