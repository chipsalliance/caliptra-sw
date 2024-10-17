// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_pmp_enforced() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::rom_tests::TEST_PMP_TESTS).unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();
    hw.step_until_exit_failure().unwrap();
}
