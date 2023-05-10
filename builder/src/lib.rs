// Licensed under the Apache-2.0 license

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use caliptra_image_elf::ElfExecutable;
use caliptra_image_gen::{
    ImageGenerator, ImageGeneratorConfig, ImageGeneratorOwnerConfig, ImageGeneratorVendorConfig,
};
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::{ImageBundle, ImageRevision};
use elf::endian::LittleEndian;

mod elf_symbols;

pub use elf_symbols::{elf_symbols, Symbol, SymbolBind, SymbolType, SymbolVisibility};
use once_cell::sync::Lazy;

pub const ROM: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &[],
};

pub const ROM_WITH_UART: FwId = FwId {
    crate_name: "caliptra-rom",
    bin_name: "caliptra-rom",
    features: &["emu"],
};

pub const FMC_WITH_UART: FwId = FwId {
    crate_name: "caliptra-fmc",
    bin_name: "caliptra-fmc",
    features: &["emu"],
};

pub const APP_WITH_UART: FwId = FwId {
    crate_name: "caliptra-runtime",
    bin_name: "caliptra-runtime",
    features: &["emu"],
};

fn other_err(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(ErrorKind::Other, e)
}

fn run_cmd(cmd: &mut Command) -> io::Result<()> {
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::Other,
            format!(
                "Process {:?} {:?} exited with status code {:?}",
                cmd.get_program(),
                cmd.get_args(),
                status.code()
            ),
        ))
    }
}

fn run_cmd_stdout(cmd: &mut Command, input: Option<&[u8]>) -> io::Result<String> {
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());

    let mut child = cmd.spawn()?;
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        std::io::Write::write_all(&mut stdin, input)?;
    }
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into())
    } else {
        Err(other_err(format!(
            "Process {:?} {:?} exited with status code {:?} stderr {}",
            cmd.get_program(),
            cmd.get_args(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )))
    }
}

// Represent the Cargo identity of a firmware binary.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct FwId<'a> {
    // The crate name (For example, "caliptra-rom")
    pub crate_name: &'a str,

    // If the crate contains multiple binaries, the name of the binary. Leave
    // empty to build the crate's default binary.
    pub bin_name: &'a str,

    // The features to use the build the binary
    pub features: &'a [&'a str],
}

pub fn build_firmware_elf_uncached(id: &FwId) -> io::Result<Vec<u8>> {
    const WORKSPACE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    const TARGET: &str = "riscv32imc-unknown-none-elf";
    const PROFILE: &str = "firmware";

    let mut features_csv = id.features.join(",");
    if !id.features.contains(&"riscv") {
        if !features_csv.is_empty() {
            features_csv.push(',');
        }
        features_csv.push_str("riscv");
    }

    let mut cmd = Command::new(env!("CARGO"));
    cmd.current_dir(WORKSPACE_DIR);
    if option_env!("GITHUB_ACTIONS").is_some() {
        // In continuous integration, warnings are always errors.
        cmd.arg("--config")
            .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]");
    }
    run_cmd(
        cmd.arg("build")
            .arg("--quiet")
            .arg("--locked")
            .arg("--target")
            .arg(TARGET)
            .arg("--features")
            .arg(features_csv)
            .arg("--no-default-features")
            .arg("--profile")
            .arg(PROFILE)
            .arg("-p")
            .arg(id.crate_name)
            .arg("--bin")
            .arg(id.bin_name),
    )?;
    fs::read(
        Path::new(WORKSPACE_DIR)
            .join("target")
            .join(TARGET)
            .join(PROFILE)
            .join(id.bin_name),
    )
}

pub fn build_firmware_elf(id: &FwId<'static>) -> io::Result<Arc<Vec<u8>>> {
    type CacheEntry = Arc<Mutex<Arc<Vec<u8>>>>;
    static CACHE: Lazy<Mutex<HashMap<FwId, CacheEntry>>> = Lazy::new(Default::default);

    let result_mutex: Arc<Mutex<Arc<Vec<u8>>>>;
    let mut result_mutex_guard;
    {
        let mut cache_guard = CACHE.lock().unwrap();
        let entry = cache_guard.entry(*id);
        match entry {
            Entry::Occupied(entry) => {
                let result = entry.get().clone();
                drop(cache_guard);
                return Ok(result.lock().unwrap().clone());
            }
            Entry::Vacant(entry) => {
                result_mutex = Default::default();
                let result_mutex_cloned = result_mutex.clone();
                result_mutex_guard = result_mutex.lock().unwrap();

                // Add the already-locked mutex to the map so other threads
                // needing the same firmware wait for us to populate it.
                entry.insert(result_mutex_cloned);
            }
        }
    }
    let result = Arc::new(build_firmware_elf_uncached(id)?);
    *result_mutex_guard = result.clone();
    Ok(result)
}

pub fn build_firmware_rom(id: &FwId<'static>) -> io::Result<Vec<u8>> {
    let elf_bytes = build_firmware_elf(id)?;
    elf2rom(&elf_bytes)
}

pub fn elf2rom(elf_bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = vec![0u8; 0x8000];
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;

    let Some(segments) = elf.segments() else {
        return Err(other_err("ELF file has no segments"))
    };
    for segment in segments {
        if segment.p_type != elf::abi::PT_LOAD {
            continue;
        }
        let file_offset = segment.p_offset as usize;
        let mem_offset = segment.p_paddr as usize;
        let len = segment.p_filesz as usize;
        let Some(src_bytes) = elf_bytes.get(file_offset..file_offset + len) else {
            return Err(other_err(format!("segment at 0x{:x} out of file bounds", segment.p_offset)));
        };
        if len == 0 {
            continue;
        }
        let Some(dest_bytes) = result.get_mut(mem_offset..mem_offset + len) else {
          return Err(other_err(format!(
                "segment at 0x{mem_offset:04x}..0x{:04x} exceeds the ROM region \
                 of 0x0000..0x{:04x}", mem_offset + len, result.len())));
        };
        dest_bytes.copy_from_slice(src_bytes);
    }
    Ok(result)
}

pub struct ImageOptions {
    pub fmc_min_svn: u32,
    pub fmc_svn: u32,
    pub app_min_svn: u32,
    pub app_svn: u32,
    pub vendor_config: ImageGeneratorVendorConfig,
    pub owner_config: Option<ImageGeneratorOwnerConfig>,
}
impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            fmc_min_svn: Default::default(),
            fmc_svn: Default::default(),
            app_min_svn: Default::default(),
            app_svn: Default::default(),
            vendor_config: caliptra_image_fake_keys::VENDOR_CONFIG_KEY_0,
            owner_config: Some(caliptra_image_fake_keys::OWNER_CONFIG),
        }
    }
}

pub fn build_and_sign_image(
    fmc: &FwId<'static>,
    app: &FwId<'static>,
    opts: ImageOptions,
) -> anyhow::Result<ImageBundle> {
    let fmc_elf = build_firmware_elf(fmc)?;
    let app_elf = build_firmware_elf(app)?;
    let gen = ImageGenerator::new(OsslCrypto::default());
    let image = gen.generate(&ImageGeneratorConfig {
        fmc: ElfExecutable::new(
            &fmc_elf,
            opts.fmc_svn,
            opts.fmc_min_svn,
            image_revision_from_git_repo()?,
        )?,
        runtime: ElfExecutable::new(
            &app_elf,
            opts.app_svn,
            opts.app_min_svn,
            image_revision_from_git_repo()?,
        )?,
        vendor_config: opts.vendor_config,
        owner_config: opts.owner_config,
    })?;
    Ok(image)
}
fn image_revision_from_git_repo() -> io::Result<ImageRevision> {
    let commit_id = run_cmd_stdout(Command::new("git").arg("rev-parse").arg("HEAD"), None)?;
    let rtl_git_status =
        run_cmd_stdout(Command::new("git").arg("status").arg("--porcelain"), None)?;
    image_revision_from_str(&commit_id, rtl_git_status.is_empty())
}

fn image_revision_from_str(commit_id_str: &str, is_clean: bool) -> io::Result<ImageRevision> {
    // (dirtdirtdirtdirtdirt)
    const DIRTY_SUFFIX: [u8; 10] = [0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47];

    let mut commit_id = ImageRevision::default();
    hex::decode_to_slice(commit_id_str.trim(), &mut commit_id).map_err(|e| {
        other_err(format!(
            "Unable to decode git commit {commit_id_str:?}: {e}"
        ))
    })?;

    if !is_clean {
        // spoil the revision because the git client is dirty
        commit_id[10..].copy_from_slice(&DIRTY_SUFFIX);
    }
    Ok(commit_id)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_build_firmware() {
        static FWID: FwId = FwId {
            crate_name: "caliptra-drivers-test-bin",
            bin_name: "test_success",
            features: &[],
        };
        // Ensure that we can build the ELF and elf2rom can parse it
        build_firmware_rom(&FWID).unwrap();
    }

    #[test]
    fn test_elf2rom_golden() {
        let rom_bytes = elf2rom(include_bytes!("testdata/example.elf")).unwrap();
        assert_eq!(&rom_bytes, include_bytes!("testdata/example.rom.golden"));
    }

    #[test]
    fn test_image_revision_from_str() {
        assert_eq!(
            image_revision_from_str("d6a462a63a9cf2dafa5bbc6cf78b1fccc308009a", true).unwrap(),
            [
                0xd6, 0xa4, 0x62, 0xa6, 0x3a, 0x9c, 0xf2, 0xda, 0xfa, 0x5b, 0xbc, 0x6c, 0xf7, 0x8b,
                0x1f, 0xcc, 0xc3, 0x08, 0x00, 0x9a
            ]
        );
        assert_eq!(
            image_revision_from_str("d6a462a63a9cf2dafa5bbc6cf78b1fccc308009a\n", true).unwrap(),
            [
                0xd6, 0xa4, 0x62, 0xa6, 0x3a, 0x9c, 0xf2, 0xda, 0xfa, 0x5b, 0xbc, 0x6c, 0xf7, 0x8b,
                0x1f, 0xcc, 0xc3, 0x08, 0x00, 0x9a
            ]
        );
        assert_eq!(
            image_revision_from_str("d6a462a63a9cf2dafa5bbc6cf78b1fccc308009a", false).unwrap(),
            [
                0xd6, 0xa4, 0x62, 0xa6, 0x3a, 0x9c, 0xf2, 0xda, 0xfa, 0x5b, 0xd1, 0x47, 0xd1, 0x47,
                0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47
            ]
        );
        assert_eq!(
            image_revision_from_str("d6a462a63a9cf2dafa5bbc6cf78b1fccc30800", false).unwrap_err().to_string(),
            "Unable to decode git commit \"d6a462a63a9cf2dafa5bbc6cf78b1fccc30800\": Invalid string length");
        assert!(image_revision_from_str("d6a462a63a9cf2dafa5bbc6cf78b1fccc308009g", true).is_err());
    }
}
