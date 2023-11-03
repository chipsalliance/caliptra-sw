// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

#[test]
fn test_asm() {
    let rom = caliptra_builder::build_firmware_rom(&firmware::rom_tests::ASM_TESTS).unwrap();
    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            iccm: &vec![0x55u8; 128 * 1024],
            dccm: &vec![0x66u8; 128 * 1024],
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    let mut output = vec![];
    hw.copy_output_until_exit_success(&mut output).unwrap();
    assert_eq!(
        std::str::from_utf8(&output),
        Ok("test_mem: [1, 1, 1, 1, 0, 0, 0, 0, \
                       0, 0, 0, 0, 1, 0, 0, 0, \
                       0, 0, 0, 0, 0, 0, 0, 0, \
                       0, 0, 0, 0, 0, 1, 1, 1, \
                       1, 0, 0, 0, 0, 0, 0, 0, \
                       0, 1, 1, 1, 1, 1122867, 1146447479, 2291772091, \
                       1, 1, 1122867, 1146447479, 2291772091, 1, 1, 1, \
                       1, 1, 1, 1, 1, 1, 1, 1]\n")
    )
}
