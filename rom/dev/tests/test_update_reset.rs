// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, ROM_WITH_UART};
use caliptra_common::{FirmwareHandoffTable, FuseLogEntry, FuseLogEntryId};
use caliptra_common::{PcrLogEntry, PcrLogEntryId};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams, ModelError, SecurityState};
use caliptra_image_fake_keys::VENDOR_CONFIG_KEY_1;
use caliptra_image_gen::ImageGenerator;
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::IMAGE_BYTE_SIZE;
use zerocopy::{AsBytes, FromBytes};

pub mod helpers;

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

    assert!(hw
        .upload_firmware(&image_bundle.to_bytes().unwrap())
        .is_ok());

    hw.step_until_output_contains("[exit] Launching FMC")
        .unwrap();

    let result = hw.mailbox_execute(0x1000_0004, &[]);
    assert!(result.is_ok());

    hw.step_until_output_contains("[fmc] Update reset").unwrap();

    // assert!(hw
    //     .upload_firmware(&image_bundle.to_bytes().unwrap())
    //     .is_ok());

    // hw.step_until_exit_success().unwrap();
}
