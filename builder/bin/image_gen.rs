// Licensed under the Apache-2.0 license

use caliptra_builder::firmware;
use caliptra_builder::ImageOptions;
use clap::{arg, value_parser, Command};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let args = Command::new("caliptra-emu")
        .about("Caliptra emulator")
        .arg(arg!(--"rom" <FILE> "ROM binary image").value_parser(value_parser!(PathBuf)))
        .arg(arg!(--"fw" <FILE> "FW bundle image").value_parser(value_parser!(PathBuf)))
        .get_matches();
    let rom_path = args.get_one::<PathBuf>("rom").unwrap();
    let fw_path = args.get_one::<PathBuf>("fw").unwrap();

    // Generate ROM Image
    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART).unwrap();

    // Generate Image Bundle
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART,
        &firmware::APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    // Generate ROM Binary
    let _ = std::fs::File::create(rom_path).unwrap().write_all(&rom);

    // Generate Image Bundle Binary
    let _ = std::fs::File::create(fw_path)
        .unwrap()
        .write_all(&image.to_bytes().unwrap());
}
