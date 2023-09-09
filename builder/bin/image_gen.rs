// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_builder::ImageOptions;
use clap::{arg, value_parser, Command};
use std::collections::HashSet;
use std::path::PathBuf;

fn main() {
    let args = Command::new("image-gen")
        .about("Caliptra firmware image builder")
        .arg(arg!(--"rom" [FILE] "ROM binary image").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--"fw" [FILE] "FW bundle image").value_parser(value_parser!(PathBuf)))
        .arg(
            arg!(--"all_elfs" [DIR] "Build all firmware elf files")
                .value_parser(value_parser!(PathBuf)),
        )
        .get_matches();

    if let Some(rom_path) = args.get_one::<PathBuf>("rom") {
        // Generate ROM Image
        let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();
        std::fs::write(rom_path, rom).unwrap();
    };

    if let Some(fw_path) = args.get_one::<PathBuf>("fw") {
        // Generate Image Bundle
        let image = caliptra_builder::build_and_sign_image(
            &firmware::FMC_WITH_UART,
            &firmware::APP_WITH_UART,
            ImageOptions::default(),
        )
        .unwrap();
        std::fs::write(fw_path, image.to_bytes().unwrap()).unwrap();
    }

    let mut used_filenames = HashSet::new();
    if let Some(all_dir) = args.get_one::<PathBuf>("all_elfs") {
        for (fwid, elf_bytes) in
            caliptra_builder::build_firmware_elfs_uncached(None, firmware::REGISTERED_FW).unwrap()
        {
            let elf_filename = fwid.elf_filename();
            if !used_filenames.insert(elf_filename.clone()) {
                panic!("Multiple fwids with filename {elf_filename}")
            }
            std::fs::write(all_dir.join(elf_filename), elf_bytes).unwrap();
        }
    }
}

#[test]
#[cfg_attr(not(feature = "slow_tests"), ignore)]
fn test_binaries_are_identical() {
    for (fwid, elf_bytes1) in
        caliptra_builder::build_firmware_elfs_uncached(None, firmware::REGISTERED_FW).unwrap()
    {
        let elf_bytes2 = caliptra_builder::build_firmware_elf_uncached(None, fwid).unwrap();

        assert!(
            elf_bytes1 == elf_bytes2,
            "binaries are not consistent in {fwid:?}"
        );
    }
}
