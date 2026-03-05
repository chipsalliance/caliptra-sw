// Licensed under the Apache-2.0 license

use anyhow::{bail, Result};
use log::{error, info};
use std::fs;
use std::io::Write;
use std::path::Path;

// TODO(clundin): This is based on the `./ci.sh` script, should instead call the builder library
// directly
fn build_rom_images(work_dir: &Path) -> Result<()> {
    let _ = fs::create_dir_all(work_dir);

    let rom_with_log_path = work_dir.join("caliptra-rom-with-log.bin");
    let rom_no_log_path = work_dir.join("caliptra-rom-no-log.bin");

    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let target_elf_dir = Path::new(&target_dir).join("riscv32imc-unknown-none-elf");

    let extra_cargo_config = "target.'cfg(all())'.rustflags = [\"-Dwarnings\"]";

    let build_rom = |path: &std::path::Path, flag: &str| -> Result<()> {
        let _ = fs::remove_dir_all(&target_elf_dir);
        let output = std::process::Command::new("cargo")
            .env("CALIPTRA_IMAGE_NO_GIT_REVISION", "1")
            .args([
                "--config",
                extra_cargo_config,
                "run",
                "-p",
                "caliptra-builder",
                "--",
                flag,
                path.to_str().unwrap(),
            ])
            .output()?;
        if !output.status.success() {
            error!("{}", String::from_utf8_lossy(&output.stdout));
            error!("{}", String::from_utf8_lossy(&output.stderr));
            bail!("Failed to build ROM with {}", flag);
        }
        Ok(())
    };

    build_rom(&rom_with_log_path, "--rom-with-log")?;
    build_rom(&rom_no_log_path, "--rom-no-log")?;

    Ok(())
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

    let frozen_image_file = "FROZEN_IMAGES.sha384sum";
    let mut file = fs::File::create(frozen_image_file)?;
    writeln!(
        file,
        "# WARNING: Do not update this file without the approval of the Caliptra TAC"
    )?;
    write!(file, "{}", sum_output)?;

    info!("Successfully updated {}", frozen_image_file);
    let _ = fs::remove_dir_all(&work_dir);

    Ok(())
}

pub fn check_frozen_images() -> Result<()> {
    info!("Checking frozen images...");

    let work_dir = std::env::temp_dir().join("caliptra_frozen_images");
    build_rom_images(&work_dir)?;

    let frozen_image_file = std::env::current_dir()?.join("FROZEN_IMAGES.sha384sum");

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
