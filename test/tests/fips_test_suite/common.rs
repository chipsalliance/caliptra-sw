// Licensed under the Apache-2.0 license

use caliptra_builder::firmware::{self, APP_WITH_UART, FMC_WITH_UART};
use caliptra_builder::ImageOptions;
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel};

// Generic helper to boot to ROM or runtime
// Builds ROM, if not provided
// HW Model will boot to runtime if image is provided
fn fips_test_init_base(
    boot_params: Option<BootParams>,
    fw_image_override: Option<&[u8]>,
) -> DefaultHwModel {
    // Create params if not provided
    let mut boot_params = boot_params.unwrap_or_default();

    // Check that ROM was not provided if the immutable_rom feature is set
    #[cfg(feature = "test_env_immutable_rom")]
    if boot_params.init_params.rom != <&[u8]>::default() {
        panic!("FIPS_TEST_SUITE ERROR: ROM cannot be provided/changed when immutable_ROM feature is set")
    }

    // Build default rom if not provided
    let rom = caliptra_builder::build_firmware_rom(firmware::rom_from_env()).unwrap();
    if boot_params.init_params.rom == <&[u8]>::default() {
        boot_params.init_params.rom = &rom;
    }

    // Add fw image override to boot params if provided
    if fw_image_override.is_some() {
        // Sanity check that the caller functions are written correctly
        if boot_params.fw_image.is_some() {
            panic!("FIPS_TEST_SUITE BUG: Should never have a fw_image override and a fw_image in boot params")
        }
        boot_params.fw_image = fw_image_override;
    }

    // Create the model
    caliptra_hw_model::new(boot_params).unwrap()
}

// Initializes caliptra to "ready_for_fw"
// Builds and uses default ROM if not provided
pub fn fips_test_init_to_rom(boot_params: Option<BootParams>) -> DefaultHwModel {
    // Check that no fw_image is in boot params
    if let Some(ref params) = boot_params {
        if params.fw_image.is_some() {
            panic!("No FW image should be provided when calling fips_test_init_to_rom")
        }
    }

    let mut model = fips_test_init_base(boot_params, None);

    // Step to ready for FW in ROM
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}

// Initializes Caliptra to runtime
// Builds and uses default ROM and FW if not provided
pub fn fips_test_init_to_rt(boot_params: Option<BootParams>) -> DefaultHwModel {
    let mut build_fw = true;

    if let Some(ref params) = boot_params {
        if params.fw_image.is_some() {
            build_fw = false;
        }
    }

    if build_fw {
        // Build FW image if not provided
        let fw_image = caliptra_builder::build_and_sign_image(
            &FMC_WITH_UART,
            &APP_WITH_UART,
            ImageOptions::default(),
        )
        .unwrap();
        fips_test_init_base(boot_params, Some(&fw_image.to_bytes().unwrap()))
    } else {
        fips_test_init_base(boot_params, None)
    }

    // HW model will complete FW upload cmd, nothing to wait for
}
