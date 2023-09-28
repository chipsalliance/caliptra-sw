// Licensed under the Apache-2.0 license

use caliptra_builder::{
    firmware::{rom_tests::TEST_FMC_WITH_UART, APP_WITH_UART, ROM_WITH_UART},
    ImageOptions,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, HwModel, InitParams};
use caliptra_image_types::RomInfo;
use zerocopy::{AsBytes, FromBytes};

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

#[test]
fn test_read_rom_info_from_fmc() {
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();
    let rom_info_from_image =
        RomInfo::read_from_prefix(&rom[find_rom_info_offset(&rom)..]).unwrap();
    let image_bundle = caliptra_builder::build_and_sign_image(
        &TEST_FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap()
    .to_bytes()
    .unwrap();

    let mut hw = caliptra_hw_model::new(BootParams {
        init_params: InitParams {
            rom: &rom,
            ..Default::default()
        },
        fw_image: Some(&image_bundle),
        ..Default::default()
    })
    .unwrap();

    // 0x1000_0008 is test-fmc/read_rom_info()
    let rom_info_from_fw = RomInfo::read_from(
        hw.mailbox_execute(0x1000_0008, &[])
            .unwrap()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    assert_eq!(rom_info_from_fw.as_bytes(), rom_info_from_image.as_bytes());
}
