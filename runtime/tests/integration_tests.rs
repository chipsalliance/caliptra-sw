// Licensed under the Apache-2.0 license.

use caliptra_builder::{FwId, ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, HwModel, InitParams};

fn run_rt_test(test_bin_name: Option<&str>) {
    let runtime_fwid = match test_bin_name {
        Some(bin) => FwId {
            crate_name: "caliptra-runtime-test-bin",
            bin_name: bin,
            features: &["emu", "riscv", "runtime"],
        },
        None => APP_WITH_UART,
    };

    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &runtime_fwid,
        ImageOptions::default(),
    )
    .unwrap();

    let mut model = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    model.upload_firmware(&image).unwrap();
}

#[test]
fn test_standard() {
    // Test that the normal runtime firmware boots.
    // Ultimately, this will be useful for exercising Caliptra end-to-end
    // via the mailbox.
    run_rt_test(None);
}

#[test]
fn test_boot() {
    run_rt_test(Some("boot"));
}
