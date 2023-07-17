// Licensed under the Apache-2.0 license

use caliptra_builder::ROM_WITH_UART;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};

fn find_rom_info_offset(rom: &[u8]) -> usize {
    for i in (0..rom.len()).step_by(64).rev() {
        if rom[i..][..64] != [0u8; 64] {
            return i;
        }
    }
    panic!("Could not find RomInfo");
}

#[test]
fn test_rom_integrity_failure() {
    let mut rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    let rom_info_offset = find_rom_info_offset(&rom);
    println!("rom_info_offset is {}", rom_info_offset);

    // Corrupt a bit in the ROM info hash (we don't want to pick an arbitrary
    // location in the image as that might make the CPU crazy)
    rom[rom_info_offset + 9] ^= 1;

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    loop {
        hw.step();
        if hw.ready_for_fw() {
            panic!("ROM should have had a failure")
        }

        if let Ok(err) = CaliptraError::try_from(hw.soc_ifc().cptra_fw_error_fatal().read()) {
            assert_eq!(err, CaliptraError::ROM_INTEGRITY_FAILURE);
            break;
        }
    }
}
