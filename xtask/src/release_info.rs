// Licensed under the Apache-2.0 license

//! Extracts release information (version, SHA hashes, git commit, SVN) from
//! Caliptra firmware releases on GitHub.
//!
//! For ROM releases the SHA256 is the digest embedded inside each ROM binary
//! and is verified by recomputation; the SHA384 is computed over the entire
//! raw ROM binary. For FW releases the SHA384 hashes are extracted from the
//! FMC and Runtime TOC entries inside the firmware image manifest (not from
//! the firmware bundle file itself).

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

const OWNER: &str = "chipsalliance";
const REPO: &str = "caliptra-sw";
const GITHUB_URL: &str = "https://github.com/chipsalliance/caliptra-sw";

// Manifest markers
const MANIFEST_MARKER_2X: u32 = 0x324E4D43; // "CMN2"
const MANIFEST_MARKER_1X: u32 = 0x4E414D43; // "CMAN"

const TOC_ENTRY_SIZE: usize = 104;
const TOC_DIGEST_OFFSET: usize = 56;
const TOC_DIGEST_SIZE: usize = 48;
const TOC_SVN_OFFSET_1X: usize = 32;
const HEADER_SVN_OFFSET_BEFORE_FMC_2X: usize = 84;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReleaseType {
    Rom,
    Fw,
}

pub struct ReleaseEntry {
    pub name: &'static str,
    pub tag: &'static str,
    pub ty: ReleaseType,
    /// Optional GitHub release tag that hosts caliptra_release*.zip.
    /// When `None`, falls back to `tag`.
    pub asset_tag: Option<&'static str>,
    /// True when there are no pre-built assets and the release must be built
    /// from source (requires the `--build` flag).
    pub build: bool,
}

#[rustfmt::skip]
pub const ALL_RELEASES: &[ReleaseEntry] = &[
    // ── ROM releases ─────────────────────────────────────────────
    ReleaseEntry { name: "rom-1.0.0", tag: "rom-1.0.0", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-1.0.1", tag: "rom-1.0.1", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-1.0.2", tag: "rom-1.0.2", ty: ReleaseType::Rom, asset_tag: Some("release_v20240522_1"), build: false },
    ReleaseEntry { name: "rom-1.0.3", tag: "rom-1.0.3", ty: ReleaseType::Rom, asset_tag: None, build: true },
    ReleaseEntry { name: "rom-1.1.0", tag: "rom-1.1.0", ty: ReleaseType::Rom, asset_tag: Some("release_v20240807_0"), build: false },
    ReleaseEntry { name: "rom-1.1.1", tag: "rom-1.1.1", ty: ReleaseType::Rom, asset_tag: Some("release_v20250107_0"), build: false },
    ReleaseEntry { name: "rom-1.2.0", tag: "rom-1.2.0", ty: ReleaseType::Rom, asset_tag: Some("release_v20241202_0"), build: false },
    ReleaseEntry { name: "rom-2.0.0", tag: "rom-2.0.0", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-2.0.1", tag: "rom-2.0.1", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-2.0.2", tag: "rom-2.0.2", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-2.1.0", tag: "rom-2.1.0", ty: ReleaseType::Rom, asset_tag: None, build: false },
    ReleaseEntry { name: "rom-2.1.1", tag: "rom-2.1.1", ty: ReleaseType::Rom, asset_tag: None, build: false },
    // ── FMC + Runtime FW releases ────────────────────────────────
    ReleaseEntry { name: "fmc-1.0.0 / rt-1.0.0", tag: "rt-1.0.0",   ty: ReleaseType::Fw, asset_tag: None, build: false },
    ReleaseEntry { name: "fmc-1.0.2 / rt-1.0.2", tag: "fmc-1.0.2",  ty: ReleaseType::Fw, asset_tag: Some("release_v20240522_1"), build: false },
    ReleaseEntry { name: "fmc-1.1.0 / rt-1.1.0", tag: "fmc-1.1.0",  ty: ReleaseType::Fw, asset_tag: Some("release_v20240807_0"), build: false },
    ReleaseEntry { name: "rt-1.2.0",  tag: "rt-1.2.0",  ty: ReleaseType::Fw, asset_tag: Some("release_v20250205_1"), build: false },
    ReleaseEntry { name: "rt-1.2.1",  tag: "rt-1.2.1",  ty: ReleaseType::Fw, asset_tag: Some("release_v20250327_0"), build: false },
    ReleaseEntry { name: "rt-1.2.2",  tag: "rt-1.2.2",  ty: ReleaseType::Fw, asset_tag: None, build: false },
    ReleaseEntry { name: "rt-1.2.3",  tag: "rt-1.2.3",  ty: ReleaseType::Fw, asset_tag: Some("release_v20251105_0"), build: false },
    ReleaseEntry { name: "rt-1.2.4",  tag: "rt-1.2.4",  ty: ReleaseType::Fw, asset_tag: Some("release_v20260312_0"), build: false },
    ReleaseEntry { name: "fw-2.0.0",  tag: "fw-2.0.0",  ty: ReleaseType::Fw, asset_tag: None, build: false },
    ReleaseEntry { name: "fw-2.0.1",  tag: "fw-2.0.1",  ty: ReleaseType::Fw, asset_tag: None, build: false },
    ReleaseEntry { name: "fw-2.1.0",  tag: "fw-2.1.0",  ty: ReleaseType::Fw, asset_tag: None, build: false },
];

#[derive(Default)]
pub struct ReleaseInfo {
    pub name: String,
    pub tag: String,
    pub commit: String,
    pub url: String,
    pub ty: Option<ReleaseType>,

    // ROM-only
    pub rom_sha384: Option<String>,
    pub rom_log_sha384: Option<String>,
    pub rom_sha256: Option<String>,
    pub rom_log_sha256: Option<String>,

    // FW-only
    pub fmc_digest: Option<String>,
    pub rt_digest: Option<String>,

    pub svn: u32,
}

fn build_octocrab() -> Result<octocrab::Octocrab> {
    let mut builder = octocrab::Octocrab::builder();
    // Use a token if one is available (raises API rate limits), otherwise
    // fall back to unauthenticated access (sufficient for public releases).
    if let Some(token) = discover_github_token() {
        builder = builder.personal_token(token);
    } else {
        eprintln!(
            "warning: no GitHub token found; falling back to unauthenticated API \
             access (subject to 60 req/hr rate limits). Set GITHUB_TOKEN or run \
             `gh auth login` to avoid rate-limit failures."
        );
    }
    Ok(builder.build()?)
}

/// Locate a GitHub token from the environment or from the GitHub CLI (`gh`).
///
/// Checks, in order:
/// 1. `GITHUB_TOKEN` / `GH_TOKEN` environment variables
/// 2. `gh auth token` (works with any `gh`-authenticated host)
fn discover_github_token() -> Option<String> {
    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let output = Command::new("gh").args(["auth", "token"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let token = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

#[derive(Deserialize)]
struct GitObject {
    #[serde(rename = "type")]
    obj_type: String,
    sha: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct RefPayload {
    object: GitObject,
}

#[derive(Deserialize)]
struct TagPayload {
    object: GitObject,
}

async fn get_tag_commit(crab: &octocrab::Octocrab, tag: &str) -> Result<String> {
    let ref_route = format!("/repos/{OWNER}/{REPO}/git/refs/tags/{tag}");
    let tag_ref: RefPayload = crab.get(&ref_route, None::<&()>).await?;
    if tag_ref.object.obj_type == "tag" {
        let url = tag_ref
            .object
            .url
            .ok_or_else(|| anyhow!("tag object missing url"))?;
        let tag_obj: TagPayload = crab.get(&url, None::<&()>).await?;
        tag_obj
            .object
            .sha
            .ok_or_else(|| anyhow!("dereferenced tag missing sha"))
    } else {
        tag_ref
            .object
            .sha
            .ok_or_else(|| anyhow!("lightweight tag missing sha"))
    }
}

async fn release_url_for_tag(crab: &octocrab::Octocrab, tag: &str) -> String {
    match crab.repos(OWNER, REPO).releases().get_by_tag(tag).await {
        Ok(r) => r.html_url.to_string(),
        Err(_) => format!("{GITHUB_URL}/releases/tag/{tag}"),
    }
}

async fn download_release_zip(
    crab: &octocrab::Octocrab,
    tag: &str,
    dest_dir: &Path,
) -> Result<PathBuf> {
    let release = crab
        .repos(OWNER, REPO)
        .releases()
        .get_by_tag(tag)
        .await
        .with_context(|| format!("failed to look up release {tag}"))?;

    let asset = release
        .assets
        .iter()
        .find(|a| a.name.starts_with("caliptra_release") && a.name.ends_with(".zip"))
        .ok_or_else(|| anyhow!("No caliptra_release*.zip asset found for tag {tag}"))?;

    let tag_dir = dest_dir.join(tag.replace('/', "_"));
    fs::create_dir_all(&tag_dir)?;
    let dest = tag_dir.join(&asset.name);

    // Public release assets are served without authentication; fetch them
    // directly via reqwest (following redirects to the storage backend).
    let client = reqwest::Client::builder()
        .user_agent("caliptra-sw-xtask")
        .build()?;
    let bytes = client
        .get(asset.browser_download_url.clone())
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    fs::write(&dest, &bytes)?;
    Ok(dest)
}

fn sha384_hex(data: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Extract and verify the embedded SHA256 from a ROM binary.
///
/// The builder computes SHA256 over the ROM bytes preceding the `RomInfo`
/// struct using a word-reversed algorithm (each 4-byte LE word is byte-swapped
/// to BE before hashing) and stores the result as `[u32; 8]` in little-endian
/// byte order.
fn extract_rom_sha256(data: &[u8], commit_hex: &str) -> Result<String> {
    const DIRTY_SUFFIX: [u8; 10] = [0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47, 0xd1, 0x47];
    let clean_rev = hex::decode(&commit_hex[..40])?;
    let mut dirty_rev = clean_rev[..10].to_vec();
    dirty_rev.extend_from_slice(&DIRTY_SUFFIX);

    let find_pos =
        |needle: &[u8]| -> Option<usize> { data.windows(needle.len()).position(|w| w == needle) };

    let rom_info_start = find_pos(&clean_rev)
        .or_else(|| find_pos(&dirty_rev))
        .and_then(|p| if p >= 32 { Some(p - 32) } else { None })
        .ok_or_else(|| {
            anyhow!(
                "Could not locate git revision {} in ROM binary",
                &commit_hex[..12]
            )
        })?;

    // Read the embedded digest (stored as [u32; 8] LE) and swap each 4-byte
    // group to get the standard SHA256 byte order.
    let embedded_raw = &data[rom_info_start..rom_info_start + 32];
    let mut embedded_std = [0u8; 32];
    for i in 0..8 {
        let w = &embedded_raw[i * 4..(i + 1) * 4];
        embedded_std[i * 4] = w[3];
        embedded_std[i * 4 + 1] = w[2];
        embedded_std[i * 4 + 2] = w[1];
        embedded_std[i * 4 + 3] = w[0];
    }

    // Recompute SHA256 with the word-reversed input algorithm.
    let mut h = Sha256::new();
    let mut i = 0;
    while i < rom_info_start {
        let word = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        h.update(word.to_be_bytes());
        i += 4;
    }
    let computed = h.finalize();

    if computed.as_slice() != embedded_std {
        bail!(
            "SHA256 mismatch in ROM: embedded {} != computed {}",
            hex::encode(embedded_std),
            hex::encode(computed)
        );
    }
    Ok(hex::encode(embedded_std))
}

struct FwInfo {
    fmc_digest: String,
    rt_digest: String,
    svn: u32,
}

fn parse_fw_bundle(data: &[u8]) -> Result<FwInfo> {
    if data.len() < 8 {
        bail!("FW bundle too small");
    }
    let marker = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let manifest_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    if marker != MANIFEST_MARKER_1X && marker != MANIFEST_MARKER_2X {
        bail!("Unknown manifest marker 0x{marker:08X}");
    }
    let is_2x = marker == MANIFEST_MARKER_2X;

    let fmc_off = manifest_size - 2 * TOC_ENTRY_SIZE;
    let rt_off = manifest_size - TOC_ENTRY_SIZE;

    let fmc_id = u32::from_le_bytes(data[fmc_off..fmc_off + 4].try_into().unwrap());
    let rt_id = u32::from_le_bytes(data[rt_off..rt_off + 4].try_into().unwrap());
    if fmc_id != 1 || rt_id != 2 {
        bail!("Unexpected TOC IDs: FMC={fmc_id}, RT={rt_id} (expected 1, 2)");
    }

    let fmc_digest = hex::encode(
        &data[fmc_off + TOC_DIGEST_OFFSET..fmc_off + TOC_DIGEST_OFFSET + TOC_DIGEST_SIZE],
    );
    let rt_digest = hex::encode(
        &data[rt_off + TOC_DIGEST_OFFSET..rt_off + TOC_DIGEST_OFFSET + TOC_DIGEST_SIZE],
    );

    let svn = if is_2x {
        u32::from_le_bytes(
            data[fmc_off - HEADER_SVN_OFFSET_BEFORE_FMC_2X
                ..fmc_off - HEADER_SVN_OFFSET_BEFORE_FMC_2X + 4]
                .try_into()
                .unwrap(),
        )
    } else {
        u32::from_le_bytes(
            data[fmc_off + TOC_SVN_OFFSET_1X..fmc_off + TOC_SVN_OFFSET_1X + 4]
                .try_into()
                .unwrap(),
        )
    };

    Ok(FwInfo {
        fmc_digest,
        rt_digest,
        svn,
    })
}

fn read_zip_entry(zip_path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    let file =
        fs::File::open(zip_path).with_context(|| format!("opening {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)?;
    let result = match archive.by_name(name) {
        Ok(mut entry) => {
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(e.into()),
    };
    result
}

fn read_bundle_from_zip(zip_path: &Path) -> Result<Vec<u8>> {
    for candidate in [
        "image-bundle-mldsa.bin",
        "image-bundle-lms.bin",
        "image-bundle.bin",
    ] {
        if let Some(bytes) = read_zip_entry(zip_path, candidate)? {
            return Ok(bytes);
        }
    }
    bail!("No firmware bundle found in {}", zip_path.display())
}

fn read_required_zip_entry(zip_path: &Path, name: &str) -> Result<Vec<u8>> {
    read_zip_entry(zip_path, name)?
        .ok_or_else(|| anyhow!("{} not found in {}", name, zip_path.display()))
}

fn build_rom_from_source(tag: &str, work_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let worktree = work_dir.join(format!("worktree_{}", tag.replace('/', "_")));
    let rom_nolog = work_dir.join(format!("caliptra-rom-{tag}.bin"));
    let rom_log = work_dir.join(format!("caliptra-rom-{tag}-with-log.bin"));

    let repo_root = {
        let out = Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()?;
        if !out.status.success() {
            bail!("git rev-parse --show-toplevel failed");
        }
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    let status = Command::new("git")
        .current_dir(&repo_root)
        .args([
            "worktree",
            "add",
            "--detach",
            worktree.to_str().unwrap(),
            tag,
        ])
        .status()?;
    if !status.success() {
        bail!("git worktree add failed for {tag}");
    }

    let result = (|| -> Result<()> {
        let status = Command::new("git")
            .current_dir(&worktree)
            .args(["submodule", "update", "--init", "dpe"])
            .status()?;
        if !status.success() {
            bail!("git submodule init failed");
        }

        // Pick up the pinned rust toolchain from the worktree, if any.
        let mut rust_channel: Option<String> = None;
        let toolchain_file = worktree.join("rust-toolchain.toml");
        if toolchain_file.exists() {
            if let Ok(content) = fs::read_to_string(&toolchain_file) {
                for line in content.lines() {
                    let t = line.trim();
                    if t.starts_with("channel") {
                        if let Some((_, rhs)) = t.split_once('=') {
                            let v = rhs.trim().trim_matches(|c: char| c == '"' || c == '\'');
                            rust_channel = Some(v.to_string());
                            break;
                        }
                    }
                }
            }
        }

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&worktree)
            .args([
                "run",
                "--release",
                "-p",
                "caliptra-builder",
                "--no-default-features",
                "--locked",
                "--",
                "--rom-no-log",
                rom_nolog.to_str().unwrap(),
                "--rom-with-log",
                rom_log.to_str().unwrap(),
            ])
            // Ensure the builder embeds the real git hash, not the placeholder.
            .env_remove("CALIPTRA_IMAGE_NO_GIT_REVISION")
            // Strip cargo/rustc overrides inherited from the parent `cargo run`
            // invocation so that rustup fully controls the toolchain for the
            // nested build (the worktree pins an older rustc via
            // rust-toolchain.toml that won't accept the parent rustc's flags).
            .env_remove("CARGO")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTDOC")
            .env_remove("CARGO_MANIFEST_DIR")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_PKG_NAME")
            .env_remove("CARGO_PKG_VERSION");
        if let Some(channel) = rust_channel {
            cmd.env("RUSTUP_TOOLCHAIN", channel);
        }
        let out = cmd.output()?;
        if !out.status.success() {
            bail!(
                "Build failed for {tag}:\n{}\n{}",
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout)
            );
        }
        Ok(())
    })();

    // Always try to clean up the worktree.
    let _ = Command::new("git")
        .current_dir(&repo_root)
        .args(["worktree", "remove", "--force", worktree.to_str().unwrap()])
        .status();

    result?;
    Ok((rom_nolog, rom_log))
}

async fn process_release(
    crab: &octocrab::Octocrab,
    entry: &ReleaseEntry,
    work_dir: &Path,
    allow_build: bool,
) -> Result<ReleaseInfo> {
    let asset_tag = entry.asset_tag.unwrap_or(entry.tag);
    let commit = get_tag_commit(crab, entry.tag).await?;
    let url = release_url_for_tag(crab, asset_tag).await;

    let mut info = ReleaseInfo {
        name: entry.name.to_string(),
        tag: entry.tag.to_string(),
        commit: commit.clone(),
        url,
        ty: Some(entry.ty),
        ..Default::default()
    };

    if entry.build && entry.ty == ReleaseType::Rom {
        if !allow_build {
            bail!(
                "{} requires building from source (pass --build)",
                entry.name
            );
        }
        let (nolog_bin, log_bin) = build_rom_from_source(entry.tag, work_dir)?;
        let nolog_data = fs::read(&nolog_bin)?;
        let log_data = fs::read(&log_bin)?;
        info.rom_sha384 = Some(sha384_hex(&nolog_data));
        info.rom_log_sha384 = Some(sha384_hex(&log_data));
        info.rom_sha256 = Some(extract_rom_sha256(&nolog_data, &commit)?);
        info.rom_log_sha256 = Some(extract_rom_sha256(&log_data, &commit)?);
        info.svn = 0;
        return Ok(info);
    }

    let zip_path = download_release_zip(crab, asset_tag, work_dir).await?;

    match entry.ty {
        ReleaseType::Rom => {
            for (name, is_log) in [
                ("caliptra-rom.bin", false),
                ("caliptra-rom-with-log.bin", true),
            ] {
                let data = read_required_zip_entry(&zip_path, name)?;
                let sha384 = sha384_hex(&data);
                let sha256 = extract_rom_sha256(&data, &commit)?;
                if is_log {
                    info.rom_log_sha384 = Some(sha384);
                    info.rom_log_sha256 = Some(sha256);
                } else {
                    info.rom_sha384 = Some(sha384);
                    info.rom_sha256 = Some(sha256);
                }
            }
            info.svn = 0;
        }
        ReleaseType::Fw => {
            let data = read_bundle_from_zip(&zip_path)?;
            let fw = parse_fw_bundle(&data)?;
            info.fmc_digest = Some(fw.fmc_digest);
            info.rt_digest = Some(fw.rt_digest);
            info.svn = fw.svn;
        }
    }

    Ok(info)
}

fn format_commit_link(commit: &str) -> String {
    let short = &commit[..7];
    format!("[`{short}`]({GITHUB_URL}/commit/{commit})")
}

fn format_release_link(name: &str, url: &str) -> String {
    format!("[{name}]({url})")
}

fn print_info(info: &ReleaseInfo) {
    println!("Release: {}", info.name);
    println!("  Tag:    {}", info.tag);
    println!("  Commit: {}", info.commit);
    println!("  URL:    {}", info.url);
    match info.ty {
        Some(ReleaseType::Rom) => {
            println!(
                "  ROM SHA256 (no log):   {}",
                info.rom_sha256.as_deref().unwrap_or("")
            );
            println!(
                "  ROM SHA256 (with log): {}",
                info.rom_log_sha256.as_deref().unwrap_or("")
            );
            println!(
                "  ROM SHA384 (no log):   {}",
                info.rom_sha384.as_deref().unwrap_or("")
            );
            println!(
                "  ROM SHA384 (with log): {}",
                info.rom_log_sha384.as_deref().unwrap_or("")
            );
            println!("  SVN: {}", info.svn);
        }
        Some(ReleaseType::Fw) => {
            println!("  FMC SHA384: {}", info.fmc_digest.as_deref().unwrap_or(""));
            println!("  RT  SHA384: {}", info.rt_digest.as_deref().unwrap_or(""));
            println!("  SVN: {}", info.svn);
        }
        None => {}
    }
}

/// Returns the compatible RTL version(s) for a given ROM/FW release name.
///
/// The mapping reflects which Caliptra RTL releases a given firmware or ROM
/// binary is known to be compatible with. For 2.0.x ROM/FW we use `2.0.2+`
/// because the 2.0.0 and 2.0.1 RTL releases have known incompatibilities that
/// are only fixed from 2.0.2 onward; all other entries pin to a specific RTL
/// major.minor line.
fn rtl_compat(name: &str, ty: ReleaseType) -> &'static str {
    // Strip the leading "rom-", "fw-", "fmc-", or "rt-" prefix and anything
    // after a space (handles combined names like "fmc-1.0.0 / rt-1.0.0").
    let version = name
        .split_whitespace()
        .next()
        .unwrap_or(name)
        .trim_start_matches("rom-")
        .trim_start_matches("fw-")
        .trim_start_matches("fmc-")
        .trim_start_matches("rt-");
    let mut parts = version.split('.');
    let major = parts.next().unwrap_or("");
    let minor = parts.next().unwrap_or("");
    match (ty, major, minor) {
        (ReleaseType::Rom, "1", "0") => "1.0",
        (ReleaseType::Rom, "1", "1") => "1.1",
        (ReleaseType::Rom, "1", "2") => "1.1",
        (ReleaseType::Rom, "2", "0") => "2.0.2+",
        (ReleaseType::Rom, "2", "1") => "2.1",
        (ReleaseType::Fw, "1", "0") => "1.0",
        (ReleaseType::Fw, "1", "1") => "1.0, 1.1",
        (ReleaseType::Fw, "1", "2") => "1.0, 1.1",
        (ReleaseType::Fw, "2", "0") => "2.0.2+",
        (ReleaseType::Fw, "2", "1") => "2.1",
        _ => "",
    }
}

fn print_markdown_tables(all: &[ReleaseInfo]) {
    let roms: Vec<&ReleaseInfo> = all
        .iter()
        .filter(|i| i.ty == Some(ReleaseType::Rom))
        .collect();
    let fws: Vec<&ReleaseInfo> = all
        .iter()
        .filter(|i| i.ty == Some(ReleaseType::Fw))
        .collect();

    if !roms.is_empty() {
        println!("### ROM Releases\n");
        println!("| Version | RTL | SHA256 (no log) | SHA256 (with log) | SHA384 (no log) | SHA384 (with log) | Git Commit | SVN |");
        println!("|---------|-----|-----------------|--------------------|-----------------|--------------------|------------|-----|");
        for r in &roms {
            let version = format_release_link(&r.name, &r.url);
            println!(
                "| {} | {} | `{}` | `{}` | `{}` | `{}` | {} | {} |",
                version,
                rtl_compat(&r.name, ReleaseType::Rom),
                r.rom_sha256.as_deref().unwrap_or(""),
                r.rom_log_sha256.as_deref().unwrap_or(""),
                r.rom_sha384.as_deref().unwrap_or(""),
                r.rom_log_sha384.as_deref().unwrap_or(""),
                format_commit_link(&r.commit),
                r.svn,
            );
        }
        println!();
    }

    if !fws.is_empty() {
        println!("### FMC+Runtime FW Releases\n");
        println!("| Version | RTL | FMC SHA384 | Runtime SHA384 | Git Commit | SVN |");
        println!("|---------|-----|------------|----------------|------------|-----|");
        for r in &fws {
            let version = format_release_link(&r.name, &r.url);
            println!(
                "| {} | {} | `{}` | `{}` | {} | {} |",
                version,
                rtl_compat(&r.name, ReleaseType::Fw),
                r.fmc_digest.as_deref().unwrap_or(""),
                r.rt_digest.as_deref().unwrap_or(""),
                format_commit_link(&r.commit),
                r.svn,
            );
        }
        println!();
    }
}

/// A simple auto-cleanup temporary directory.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = base.join(format!("caliptra-release-{pid}-{nanos}"));
        fs::create_dir_all(&dir)?;
        Ok(TempDir(dir))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run(release_name: Option<&str>, markdown: bool, build: bool) -> Result<()> {
    let work = TempDir::new()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let crab = build_octocrab()?;
        if let Some(name) = release_name {
            let entry = ALL_RELEASES
                .iter()
                .find(|e| e.name == name || e.tag == name)
                .ok_or_else(|| anyhow!("Release '{name}' not found"))?;
            let info = process_release(&crab, entry, work.path(), build).await?;
            if markdown {
                print_markdown_tables(std::slice::from_ref(&info));
            } else {
                print_info(&info);
            }
        } else {
            let mut all_info: Vec<ReleaseInfo> = Vec::new();
            for entry in ALL_RELEASES {
                match process_release(&crab, entry, work.path(), build).await {
                    Ok(info) => {
                        if !markdown {
                            print_info(&info);
                            println!();
                        }
                        all_info.push(info);
                    }
                    Err(e) => {
                        eprintln!("WARNING: Failed to process {}: {:#}", entry.name, e);
                    }
                }
            }
            if markdown {
                print_markdown_tables(&all_info);
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtl_compat_rom() {
        assert_eq!(rtl_compat("rom-1.0.0", ReleaseType::Rom), "1.0");
        assert_eq!(rtl_compat("rom-1.0.3", ReleaseType::Rom), "1.0");
        assert_eq!(rtl_compat("rom-1.1.0", ReleaseType::Rom), "1.1");
        assert_eq!(rtl_compat("rom-1.1.1", ReleaseType::Rom), "1.1");
        assert_eq!(rtl_compat("rom-1.2.0", ReleaseType::Rom), "1.1");
        assert_eq!(rtl_compat("rom-2.0.0", ReleaseType::Rom), "2.0.2+");
        assert_eq!(rtl_compat("rom-2.0.2", ReleaseType::Rom), "2.0.2+");
        assert_eq!(rtl_compat("rom-2.1.0", ReleaseType::Rom), "2.1");
        assert_eq!(rtl_compat("rom-2.1.1", ReleaseType::Rom), "2.1");
    }

    #[test]
    fn rtl_compat_fw() {
        assert_eq!(rtl_compat("fmc-1.0.0 / rt-1.0.0", ReleaseType::Fw), "1.0");
        assert_eq!(
            rtl_compat("fmc-1.1.0 / rt-1.1.0", ReleaseType::Fw),
            "1.0, 1.1"
        );
        assert_eq!(rtl_compat("rt-1.2.0", ReleaseType::Fw), "1.0, 1.1");
        assert_eq!(rtl_compat("rt-1.2.4", ReleaseType::Fw), "1.0, 1.1");
        assert_eq!(rtl_compat("fw-2.0.0", ReleaseType::Fw), "2.0.2+");
        assert_eq!(rtl_compat("fw-2.0.1", ReleaseType::Fw), "2.0.2+");
        assert_eq!(rtl_compat("fw-2.1.0", ReleaseType::Fw), "2.1");
    }
}
