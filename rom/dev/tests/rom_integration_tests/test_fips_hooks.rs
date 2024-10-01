// Licensed under the Apache-2.0 license

use caliptra_api::SocManager;
use caliptra_builder::firmware::{APP_WITH_UART, FMC_WITH_UART, ROM_WITH_FIPS_TEST_HOOKS};
use caliptra_builder::ImageOptions;
use caliptra_drivers::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_fips_hook_exit() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_FIPS_TEST_HOOKS).unwrap();

    let image_bundle = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    let init_params = InitParams {
        rom: &rom,
        ..Default::default()
    };

    let boot_params = BootParams {
        fw_image: Some(&image_bundle),
        ..Default::default()
    };

    let mut hw = caliptra_hw_model::new(init_params, boot_params).unwrap();

    // Wait for fatal error
    hw.step_until(|m| m.soc_ifc().cptra_fw_error_fatal().read() != 0);

    // Verify fatal code is correct
    assert_eq!(
        hw.soc_ifc().cptra_fw_error_fatal().read(),
        u32::from(CaliptraError::ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT)
    );
}
