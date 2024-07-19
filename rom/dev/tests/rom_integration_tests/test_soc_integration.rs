// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_soc_integration() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::rom_tests::SOC_TESTS).unwrap();
    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            iccm: &vec![0x55u8; 128 * 1024],
            dccm: &vec![0x66u8; 128 * 1024],
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    let mut output = vec![];
    hw.copy_output_until_exit_success(&mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output),
        Ok("FUSE_WR_DONE = 1\n\
            VALID_PAUSER[0] = 1\n\
            FUSE_LIFE_CYCLE = 0\n")
    );

    assert_eq!(hw.soc_ifc().cptra_boot_status().read(), 0xffu32);
}
