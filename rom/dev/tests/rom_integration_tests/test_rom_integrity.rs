// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::SocManager;
use caliptra_builder::{
    firmware::{rom_tests::TEST_FMC_WITH_UART, APP_WITH_UART},
    ImageOptions,
};
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{BootParams, Fuses, HwModel, InitParams};
use caliptra_image_types::RomInfo;
use zerocopy::{FromBytes, IntoBytes};

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
    let mut rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();

    let rom_info_offset = find_rom_info_offset(&rom);
    println!("rom_info_offset is {}", rom_info_offset);

    // Corrupt a bit in the ROM info hash (we don't want to pick an arbitrary
    // location in the image as that might make the CPU crazy)
    rom[rom_info_offset + 9] ^= 1;

    let mut hw = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();

    loop {
        hw.step();
        if hw.ready_for_fw() && !hw.subsystem_mode() {
            // Subsystem says it's always ready for firmware
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
    for pqc_key_type in helpers::PQC_KEY_TYPE.iter() {
        let image_options = ImageOptions {
            pqc_key_type: *pqc_key_type,
            ..Default::default()
        };
        let fuses = Fuses {
            fuse_pqc_key_type: *pqc_key_type as u32,
            ..Default::default()
        };
        let rom = caliptra_builder::build_firmware_rom(crate::helpers::rom_from_env()).unwrap();
        let (rom_info_from_image, _) =
            RomInfo::ref_from_prefix(&rom[find_rom_info_offset(&rom)..]).unwrap();
        let image_bundle = caliptra_builder::build_and_sign_image(
            &TEST_FMC_WITH_UART,
            &APP_WITH_UART,
            image_options,
        )
        .unwrap()
        .to_bytes()
        .unwrap();

        let mut hw = caliptra_hw_model::new(
            InitParams {
                fuses,
                rom: &rom,
                ..Default::default()
            },
            BootParams {
                fw_image: Some(&image_bundle),
                ..Default::default()
            },
        )
        .unwrap();
        hw.step_until_boot_status(u32::from(ColdResetComplete), true);

        // 0x1000_0008 is test-fmc/read_rom_info()
        let rom_info_from_hw = hw.mailbox_execute(0x1000_0008, &[]).unwrap().unwrap();
        let rom_info_from_fw = RomInfo::ref_from_bytes(&rom_info_from_hw).unwrap();
        assert_eq!(rom_info_from_fw.as_bytes(), rom_info_from_image.as_bytes());
    }
}
