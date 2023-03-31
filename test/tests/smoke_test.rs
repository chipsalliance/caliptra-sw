// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{HwModel, InitParams};

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

#[test]
fn smoke_test() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
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
    let output = String::from_utf8_lossy(&output);
    assert_output_contains(&output, "Running Caliptra ROM");
    assert_output_contains(&output, "[cold-reset]");
    assert_output_contains(&output, "Running Caliptra FMC");
    assert_output_contains(
        &output,
        r#"
 / ___|__ _| (_)_ __ | |_ _ __ __ _  |  _ \_   _|
| |   / _` | | | '_ \| __| '__/ _` | | |_) || |
| |__| (_| | | | |_) | |_| | | (_| | |  _ < | |
 \____\__,_|_|_| .__/ \__|_|  \__,_| |_| \_\|_|"#,
    );
}
