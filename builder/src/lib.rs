// Licensed under the Apache-2.0 license

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use caliptra_image_elf::ElfExecutable;
use caliptra_image_gen::{
    ImageGenerator, ImageGeneratorConfig, ImageGeneratorOwnerConfig, ImageGeneratorVendorConfig,
};
use caliptra_image_openssl::OsslCrypto;
use caliptra_image_types::{ImageBundle, ImageRevision, RomInfo};
use elf::endian::LittleEndian;
use nix::fcntl::FlockArg;
use zerocopy::AsBytes;

mod elf_symbols;
pub mod firmware;
mod sha256;

pub use elf_symbols::{elf_symbols, Symbol, SymbolBind, SymbolType, SymbolVisibility};
use once_cell::sync::Lazy;

pub const THIS_WORKSPACE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct FwId<'a> {
    // The crate name (For example, "caliptra-rom")
    pub crate_name: &'a str,

    // The name of the binary inside the crate. Set to the same as crate_name
    // for a binary crate.
    pub bin_name: &'a str,

    // The features to use the build the binary
    pub features: &'a [&'a str],
}

/// Calls out to Cargo to build a firmware elf file. `workspace_dir` is the
/// workspace dir to build from; defaults to this workspace. `id` is the id of
/// the firmware to build. The result is the raw elf bytes.
pub fn build_firmware_elf_uncached(workspace_dir: Option<&Path>, id: &FwId) -> io::Result<Vec<u8>> {
    let fwids = [id];
    let result = build_firmware_elfs_uncached(workspace_dir, &fwids)?;
    if result.len() != 1 {
        panic!("Bug: build_firmware_elfs_uncached built more firmware than expected");
    }
    Ok(result.into_iter().next().unwrap().1)
}

/// Calls out to Cargo to build a firmware elf file, combining targets to
/// extract as much parallelism as possible. `workspace_dir` is the workspace
/// dir to build from; defaults to this workspace. `fwids` are the ids of the
/// firmware to build. The results will be returned in the same order as fwids,
/// with any duplicates filtered out.
pub fn build_firmware_elfs_uncached<'a>(
    workspace_dir: Option<&Path>,
    fwids: &'a [&'a FwId<'a>],
) -> io::Result<Vec<(&'a FwId<'a>, Vec<u8>)>> {
    const TARGET: &str = "riscv32imc-unknown-none-elf";
    const PROFILE: &str = "firmware";

    let cargo_invocations = cargo_invocations_from_fwids(fwids)?;

    let mut result_map = HashMap::new();

    for invocation in cargo_invocations {
        let mut features_csv = invocation.features.join(",");
        if !invocation.features.contains(&"riscv") {
            if !features_csv.is_empty() {
                features_csv.push(',');
            }
            features_csv.push_str("riscv");
        }

        let workspace_dir = workspace_dir.unwrap_or_else(|| Path::new(THIS_WORKSPACE_DIR));

        // To prevent a race condition with concurrent calls to caliptra-builder
        // from other threads or processes, hold a lock until we've read the output
        // binary from the filesystem (it's possible that another thread will build
        // the same binary with different features before we get a chance to read it).
        let _ = fs::create_dir(workspace_dir.join("target"));
        let lock = File::create(workspace_dir.join("target/.caliptra-builder.lock"))?;
        nix::fcntl::flock(lock.as_raw_fd(), FlockArg::LockExclusive)?;

        let mut cmd = Command::new(env!("CARGO"));
        cmd.current_dir(workspace_dir);
        if option_env!("GITHUB_ACTIONS").is_some() {
            // In continuous integration, warnings are always errors.
            cmd.arg("--config")
                .arg("target.'cfg(all())'.rustflags = [\"-Dwarnings\"]");
        }
        cmd.arg("build")
            .arg("--quiet")
            .arg("--locked")
            .arg("--target")
            .arg(TARGET)
            .arg("--features")
            .arg(features_csv)
            .arg("--no-default-features")
            .arg("--profile")
            .arg(PROFILE);

        cmd.arg("-p").arg(invocation.crate_name);
        for &fwid in invocation.fwids.iter() {
            cmd.arg("--bin").arg(fwid.bin_name);
        }
        run_cmd(&mut cmd)?;

        for &fwid in invocation.fwids.iter() {
            result_map.insert(
                fwid,
                fs::read(
                    Path::new(workspace_dir)
                        .join("target")
                        .join(TARGET)
                        .join(PROFILE)
                        .join(fwid.bin_name),
                )?,
            );
        }
    }
    Ok(fwids
        .iter()
        .map(|&fwid| {
            (
                fwid,
                result_map.remove(fwid).expect(
                    "Bug: cargo_invocations_from_fwid did not complain about duplicate fwid",
                ),
            )
        })
        .collect())
}

/// Compute the minimum number of cargo invocations to build all the specified
/// fwids.
fn cargo_invocations_from_fwids<'a>(
    fwids: &'a [&'a FwId<'a>],
) -> io::Result<Vec<CargoInvocation<'a>>> {
    {
        let mut fwid_set = HashSet::new();
        for fwid in fwids {
            if !fwid_set.insert(fwid) {
                return Err(other_err(format!("Duplicate FwId: {fwid:?}")));
            }
        }
    }
    let mut result = vec![];
    let mut remaining_fwids = fwids.to_vec();
    while !remaining_fwids.is_empty() {
        // Maps (crate_name, features) to CargoInvocation
        let mut invocation_map: HashMap<(&str, &[&str]), CargoInvocation> = HashMap::new();

        remaining_fwids.retain(|&fwid| {
            let invocation = invocation_map
                .entry((fwid.crate_name, fwid.features))
                .or_insert_with(|| CargoInvocation::new(fwid.crate_name, fwid.features));
            if invocation
                .fwids
                .iter()
                .any(|&x| x.bin_name == fwid.bin_name)
            {
                // The binary filenames will collide in the target directory;
                // keep fwid in remaining_fwids and build this one in a separate
                // cargo invocation.
                return true;
            }
            invocation.fwids.push(fwid);

            // remove fwid from remaining_fwids
            false
        });
        result.extend(invocation_map.into_values());
    }
    // Make the result order consistent for unit tests, and run the largest invocations first.
    result.sort_unstable_by(|a, b| {
        b.fwids
            .len()
            .cmp(&a.fwids.len())
            .then_with(|| a.crate_name.cmp(b.crate_name))
            .then_with(|| a.features.cmp(b.features))
            .then_with(|| a.fwids.cmp(&b.fwids))
    });

    Ok(result)
}

#[derive(Debug, Eq, PartialEq)]
struct CargoInvocation<'a> {
    features: &'a [&'a str],
    crate_name: &'a str,
    fwids: Vec<&'a FwId<'a>>,
}
impl<'a> CargoInvocation<'a> {
    fn new(crate_name: &'a str, features: &'a [&'a str]) -> Self {
        Self {
            features,
            crate_name,
            fwids: Vec::new(),
        }
    }
}

pub fn build_firmware_elf(id: &FwId<'static>) -> io::Result<Arc<Vec<u8>>> {
    type CacheEntry = Arc<Mutex<Arc<Vec<u8>>>>;
    static CACHE: Lazy<Mutex<HashMap<FwId, CacheEntry>>> = Lazy::new(|| {
        let result = HashMap::new();
        Mutex::new(result)
    });
    if !crate::firmware::REGISTERED_FW.contains(&id) {
        return Err(other_err(format!("FwId has not been registered. Make sure it has been added to the REGISTERED_FW array: {id:?}")));
    }

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
    let result = Arc::new(build_firmware_elf_uncached(None, id)?);
    *result_mutex_guard = result.clone();
    Ok(result)
}

pub fn build_firmware_rom(id: &FwId<'static>) -> io::Result<Vec<u8>> {
    let elf_bytes = build_firmware_elf(id)?;
    elf2rom(&elf_bytes)
}

pub fn elf2rom(elf_bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut result = vec![0u8; 0xC000];
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

    let symbols = elf_symbols(elf_bytes)?;
    if let Some(rom_info_sym) = symbols.iter().find(|s| s.name == "CALIPTRA_ROM_INFO") {
        let rom_info_start = rom_info_sym.value as usize;

        let rom_info = RomInfo {
            sha256_digest: sha256::sha256_word_reversed(&result[0..rom_info_start]),
            revision: image_revision_from_git_repo()?,
            flags: 0,
        };
        let rom_info_dest = result
            .get_mut(rom_info_start..rom_info_start + size_of::<RomInfo>())
            .ok_or_else(|| other_err("No space in ROM for CALIPTRA_ROM_INFO"))?;
        rom_info_dest.copy_from_slice(rom_info.as_bytes());
    }

    Ok(result)
}

pub fn elf_size(elf_bytes: &[u8]) -> io::Result<u64> {
    let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).map_err(other_err)?;
    let Some(segments) = elf.segments() else {
        return Err(other_err("ELF file has no segments"))
    };
    let mut min_addr = u64::MAX;
    let mut max_addr = u64::MIN;
    for segment in segments {
        if segment.p_type != elf::abi::PT_LOAD || segment.p_filesz == 0 {
            continue;
        }
        min_addr = min_addr.min(segment.p_paddr);
        max_addr = max_addr.max(segment.p_paddr + segment.p_filesz);
    }
    Ok(if max_addr >= min_addr {
        max_addr - min_addr
    } else {
        0
    })
}

#[derive(Clone)]
pub struct ImageOptions {
    pub fmc_version: u32,
    pub fmc_min_svn: u32,
    pub fmc_svn: u32,
    pub app_version: u32,
    pub app_min_svn: u32,
    pub app_svn: u32,
    pub vendor_config: ImageGeneratorVendorConfig,
    pub owner_config: Option<ImageGeneratorOwnerConfig>,
}
impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            fmc_version: Default::default(),
            fmc_min_svn: Default::default(),
            fmc_svn: Default::default(),
            app_version: Default::default(),
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
            opts.fmc_version,
            opts.fmc_svn,
            opts.fmc_min_svn,
            image_revision_from_git_repo()?,
        )?,
        runtime: ElfExecutable::new(
            &app_elf,
            opts.app_version,
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
        // Ensure that we can build the ELF and elf2rom can parse it
        build_firmware_rom(&firmware::caliptra_builder_tests::FWID).unwrap();
    }

    #[test]
    fn test_build_firmware_not_registered() {
        static FWID: FwId = FwId {
            crate_name: "caliptra-drivers-test-bin",
            bin_name: "test_success2",
            features: &[],
        };
        // Ensure that we can build the ELF and elf2rom can parse it
        let err = build_firmware_rom(&FWID).unwrap_err();
        assert!(err.to_string().contains(
            "FwId has not been registered. Make sure it has been added to the REGISTERED_FW array"
        ));
    }

    #[test]
    fn test_elf2rom_golden() {
        let rom_bytes = elf2rom(include_bytes!("testdata/example.elf")).unwrap();
        assert_eq!(&rom_bytes, include_bytes!("testdata/example.rom.golden"));
    }

    #[test]
    fn test_elf_size() {
        assert_eq!(
            elf_size(include_bytes!("testdata/example.elf")).unwrap(),
            4096
        );
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

    mod cargo_invocations_from_fwid {
        use super::*;

        #[test]
        fn test_success() {
            let fwids = [
                &FwId {
                    crate_name: "initech-firmware",
                    bin_name: "initech-firmware",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "initech-firmware",
                    bin_name: "initech-firmware",
                    features: &["pc-load-letter", "uart"],
                },
                &FwId {
                    crate_name: "test-fw",
                    bin_name: "test1",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "test-fw",
                    bin_name: "test2",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "test-fw",
                    bin_name: "test2",
                    features: &["pc-load-letter", "uart"],
                },
                &FwId {
                    crate_name: "test-fw",
                    bin_name: "test3",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "test-fw2",
                    bin_name: "test1",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "test-fw2",
                    bin_name: "test4",
                    features: &["pc-load-letter"],
                },
            ];

            assert_eq!(
                vec![
                    CargoInvocation {
                        features: &["pc-load-letter",],
                        crate_name: "test-fw",
                        fwids: vec![
                            &FwId {
                                crate_name: "test-fw",
                                bin_name: "test1",
                                features: &["pc-load-letter",],
                            },
                            &FwId {
                                crate_name: "test-fw",
                                bin_name: "test2",
                                features: &["pc-load-letter",],
                            },
                            &FwId {
                                crate_name: "test-fw",
                                bin_name: "test3",
                                features: &["pc-load-letter",],
                            },
                        ]
                    },
                    CargoInvocation {
                        features: &["pc-load-letter",],
                        crate_name: "test-fw2",
                        fwids: vec![
                            &FwId {
                                crate_name: "test-fw2",
                                bin_name: "test1",
                                features: &["pc-load-letter",],
                            },
                            &FwId {
                                crate_name: "test-fw2",
                                bin_name: "test4",
                                features: &["pc-load-letter",],
                            },
                        ],
                    },
                    CargoInvocation {
                        features: &["pc-load-letter",],
                        crate_name: "initech-firmware",
                        fwids: vec![&FwId {
                            crate_name: "initech-firmware",
                            bin_name: "initech-firmware",
                            features: &["pc-load-letter"],
                        },],
                    },
                    CargoInvocation {
                        features: &["pc-load-letter", "uart",],
                        crate_name: "initech-firmware",
                        fwids: vec![&FwId {
                            crate_name: "initech-firmware",
                            bin_name: "initech-firmware",
                            features: &["pc-load-letter", "uart",],
                        },]
                    },
                    CargoInvocation {
                        features: &["pc-load-letter", "uart",],
                        crate_name: "test-fw",
                        fwids: vec![&FwId {
                            crate_name: "test-fw",
                            bin_name: "test2",
                            features: &["pc-load-letter", "uart",],
                        },],
                    },
                ],
                cargo_invocations_from_fwids(&fwids).unwrap()
            )
        }

        #[test]
        fn test_duplicate() {
            let fwids = [
                &FwId {
                    crate_name: "initech-firmware",
                    bin_name: "initech-firmware",
                    features: &["pc-load-letter"],
                },
                &FwId {
                    crate_name: "initech-firmware",
                    bin_name: "initech-firmware",
                    features: &["pc-load-letter"],
                },
            ];
            assert!(cargo_invocations_from_fwids(&fwids)
                .unwrap_err()
                .to_string()
                .contains("Duplicate FwId"));
        }
    }
}
