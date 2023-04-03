// Licensed under the Apache-2.0 license
use caliptra_builder::{FwId, ImageOptions, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{HwModel, InitParams};

#[test]
fn test_hand_off() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    pub const MOCK_RT_WITH_UART: FwId = FwId {
        crate_name: "caliptra-fmc-mock-rt",
        bin_name: "caliptra-fmc-mock-rt",
        features: &["emu"],
    };

    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &MOCK_RT_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::create(InitParams {
        rom: &rom,
        ..Default::default()
    })
    .unwrap();
    hw.upload_firmware(&image).unwrap();
    let mut output = vec![];
    hw.copy_output_until_exit_success(&mut output).unwrap();
}
