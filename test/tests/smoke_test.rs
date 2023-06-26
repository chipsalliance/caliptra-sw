// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use std::io::Write;

#[track_caller]
fn assert_output_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "Expected substring in output not found: {needle}"
    );
}

#[test]
fn smoke_test() {
    #[cfg(not(feature = "fpga_realtime"))]
    let (rom, fmc, app) = { (ROM_WITH_UART, FMC_WITH_UART, APP_WITH_UART) };

    #[cfg(feature = "fpga_realtime")]
    let (rom, fmc, app) = {
        let mut rom_copy = ROM_WITH_UART;
        let mut fmc_copy = FMC_WITH_UART;
        let mut app_copy = APP_WITH_UART;

        rom_copy.features = &["emu fpga_realtime"];
        fmc_copy.features = &["emu fpga_realtime"];
        app_copy.features = &["emu test_only_commands fpga_realtime"];

        (rom_copy, fmc_copy, app_copy)
    };

    let rom = caliptra_builder::build_firmware_rom(&rom).unwrap();
    let image =
        caliptra_builder::build_and_sign_image(&fmc, &app, ImageOptions::default()).unwrap();
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

    hw.step_until_output_contains("Caliptra RT listening for mailbox commands...")
        .unwrap();
    output
        .write_all(hw.output().take(usize::MAX).as_bytes())
        .unwrap();

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
