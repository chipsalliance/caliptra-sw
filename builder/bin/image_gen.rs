// Licensed under the Apache-2.0 license

use caliptra_builder::{ImageOptions, APP_WITH_UART, FMC_WITH_UART, ROM_WITH_UART};
use std::io::Write;

fn main() {
    // Generate ROM Image
    let rom = caliptra_builder::build_firmware_rom(&ROM_WITH_UART).unwrap();

    // Generate Image Bundle
    let image = caliptra_builder::build_and_sign_image(
        &FMC_WITH_UART,
        &APP_WITH_UART,
        ImageOptions::default(),
    )
    .unwrap();

    // Create "out" folder if doesn`t exist
    if !std::path::Path::new("out").exists() {
        std::fs::create_dir("out").unwrap();
    }

    // Generate ROM Binary
    let _ = std::fs::File::create("out/caliptra-rom.bin")
        .unwrap()
        .write_all(&rom);

    // Generate Image Bundle Binary
    let _ = std::fs::File::create("out/image-bundle.bin")
        .unwrap()
        .write_all(&image.to_bytes().unwrap());
}
