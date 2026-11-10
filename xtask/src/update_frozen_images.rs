// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::fs;
use std::io::Write;
use std::path::Path;

use caliptra_builder::{build_firmware_rom, firmware};

fn build_rom_images(work_dir: &Path) -> Result<()> {
    let _ = fs::create_dir_all(work_dir);

    // By default, do not bake the git revision into the ROM image.
    // This follows the behaviour of ci.sh.
    if std::env::var("CALIPTRA_IMAGE_NO_GIT_REVISION").is_err() {
        std::env::set_var("CALIPTRA_IMAGE_NO_GIT_REVISION", "1");
    }

    let rom_no_log_path = work_dir.join("caliptra-rom-no-log.bin");
    let rom = build_firmware_rom(&firmware::ROM)?;
    std::fs::write(rom_no_log_path, rom)?;

    let rom_with_log_path = work_dir.join("caliptra-rom-with-log.bin");
    let rom = build_firmware_rom(&firmware::ROM_WITH_UART)?;
    std::fs::write(rom_with_log_path, rom)?;

    Ok(())
}

fn frozen_image_filename() -> String {
    let hw_revision = std::env::var("CALIPTRA_HW_REV").unwrap_or("latest".to_string());
    format!("FROZEN_IMAGES.{}.sha384sum", hw_revision)
}

pub fn update_frozen_images() -> Result<()> {
    info!("Updating frozen images...");

    let work_dir = std::env::temp_dir().join("caliptra_frozen_images");
    build_rom_images(&work_dir)?;

    let status = std::process::Command::new("sha384sum")
        .current_dir(&work_dir)
        .args(["caliptra-rom-no-log.bin", "caliptra-rom-with-log.bin"])
        .output()?;

    if !status.status.success() {
        bail!("Failed to calculate sha384sum");
    }

    let sum_output = String::from_utf8_lossy(&status.stdout);
    let filename = frozen_image_filename();

    let mut file = fs::File::create(&filename)?;
    writeln!(
        file,
        "# WARNING: Do not update this file without the approval of the Caliptra TAC"
    )?;
    write!(file, "{}", sum_output)?;

    info!("Successfully updated {}", &filename);
    let _ = fs::remove_dir_all(&work_dir);

    Ok(())
}

pub fn check_frozen_images() -> Result<()> {
    info!("Checking frozen images...");

    let work_dir = std::env::temp_dir().join("caliptra_frozen_images");
    build_rom_images(&work_dir)?;

    let frozen_image_file = std::env::current_dir()?.join(frozen_image_filename());

    let output = std::process::Command::new("sha384sum")
        .current_dir(&work_dir)
        .arg("-c")
        .arg(&frozen_image_file)
        .output()?;

    let _ = fs::remove_dir_all(&work_dir);

    if !output.status.success() {
        error!("{}", String::from_utf8_lossy(&output.stdout));
        error!("{}", String::from_utf8_lossy(&output.stderr));
        error!("The Caliptra ROM is frozen; changes that affect the binary");
        error!("require approval from the TAC.");
        error!("");
        error!("If you have approval, run `cargo xtask update-frozen-images`");
        bail!("Frozen images check failed");
    }

    info!("Frozen images check passed!");

    Ok(())
}
