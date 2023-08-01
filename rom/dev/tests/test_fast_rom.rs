// Licensed under the Apache-2.0 license

use caliptra_builder::ROM_FAST_WITH_UART;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_skip_kats() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_FAST_WITH_UART).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // If KatStarted boot status is posted before ColResetStarted, the statement below will trigger panic.
    hw.step_until_boot_status(
        caliptra_common::RomBootStatus::ColdResetStarted.into(),
        false,
    );
}
