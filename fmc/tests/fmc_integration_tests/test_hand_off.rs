// Licensed under the Apache-2.0 license
use caliptra_builder::{firmware, ImageOptions};
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_hand_off() {
    let rom = caliptra_builder::rom_for_fw_integration_tests().unwrap();

    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::runtime_tests::BOOT,
        ImageOptions::default(),
    )
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image.to_bytes().unwrap()),
        ..Default::default()
    })
    .unwrap();

    let mut output = vec![];
    hw.copy_output_until_exit_success(&mut output).unwrap();
}
