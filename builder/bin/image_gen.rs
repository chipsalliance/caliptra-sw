// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_builder::ImageOptions;
use clap::{arg, value_parser, Command};
use std::path::PathBuf;

fn main() {
    let args = Command::new("image-gen")
        .about("Caliptra firmware image builder")
        .arg(arg!(--"rom" [FILE] "ROM binary image").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--"fw" [FILE] "FW bundle image").value_parser(value_parser!(PathBuf)))
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
}
