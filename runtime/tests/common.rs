// Licensed under the Apache-2.0 license

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, DefaultHwModel, HwModel, InitParams};

// Run test_bin as a ROM image. The is used for faster tests that can run
// against verilator
pub fn run_rom_test(test_bin_name: &'static str) -> DefaultHwModel {
    static FEATURES: &[&str] = &["emu", "riscv"];

    let runtime_fwid = FwId {
        crate_name: "caliptra-runtime-test-bin",
        bin_name: test_bin_name,
        features: FEATURES,
        ..Default::default()
    };

    let rom = caliptra_builder::build_firmware_rom(&runtime_fwid).unwrap();

    caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap()
}

// Run a test which boots ROM -> FMC -> test_bin. If test_bin_name is None,
// run the production runtime image.
pub fn run_rt_test(test_bin_name: Option<&'static str>) -> DefaultHwModel {
    let runtime_fwid = match test_bin_name {
        Some(bin) => FwId {
            crate_name: "caliptra-runtime-test-bin",
            bin_name: bin,
            features: &["emu", "riscv", "runtime"],
            ..Default::default()
        },
        None => APP_WITH_UART,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let mut image_options = ImageOptions::default();
    image_options.vendor_config.pl0_pauser = Some(0xFFFF0000);
    image_options.fmc_version = 0xaaaaaaaa;
    image_options.app_version = 0xbbbbbbbb;
    let image =
        caliptra_builder::build_and_sign_image(&FMC_WITH_UART, &runtime_fwid, image_options)
            .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_fw());

    model
}
