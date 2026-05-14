// Licensed under the Apache-2.0 license

use std::{env, error::Error, io, path::Path};

use anyhow::anyhow;
use caliptra_builder::{elf_size, firmware, FwId};
use sha2::Digest;
use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};
use zip::write::FileOptions;
use zip::CompressionMethod;

const CACHE_FORMAT_VERSION: &str = "v4";

pub(crate) fn size_history() -> Result<(), anyhow::Error> {
    let cache = create_cache().map_err(|e| anyhow::anyhow!("{}", e))?;
    let reporter = HtmlTableReport::new("https://github.com/chipsalliance/caliptra-sw");
    let output: Box<dyn OutputDestination> = if env::var("GITHUB_STEP_SUMMARY").is_ok() {
        Box::new(GitHubStepSummary)
    } else {
        Box::new(Stdout)
    };

    SizeHistory::new(reporter, output, cache)
        .worktree_path("/tmp/caliptra-size-history-wt")
        .cache_version(CACHE_FORMAT_VERSION)
        .with_pr_squashing(true)
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "ROM prod size",
            firmware::ROM,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "ROM with-uart size",
            firmware::ROM_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "FMC size",
            firmware::FMC_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "App size",
            firmware::APP_WITH_UART,
        )))
        .add_builder(Box::new(CaliptraFirmwareBuilder::new(
            "App with OCP LOCK size",
            firmware::APP_WITH_UART_OCP_LOCK,
        )))
        .run()
        .map_err(|e| anyhow::anyhow!("{}", e))
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

/// Builds Caliptra firmware using caliptra_builder and measures ELF size.
struct CaliptraFirmwareBuilder {
    name: String,
    fwid: FwId<'static>,
}

impl CaliptraFirmwareBuilder {
    fn new(name: impl Into<String>, fwid: FwId<'static>) -> Self {
        Self {
            name: name.into(),
            fwid,
        }
    }

    fn build_elf(&self, workspace: &Path) -> io::Result<u64> {
        let elf_bytes = caliptra_builder::build_firmware_elf_uncached(Some(workspace), &self.fwid)?;
        elf_size(&elf_bytes)
    }
}

impl ArtifactBuilder for CaliptraFirmwareBuilder {
    fn name(&self) -> &str {
        &self.name
    }

    fn build_and_measure(&self, workspace: &Path) -> Option<u64> {
        match self.build_elf(workspace) {
            Ok(size) => Some(size),
            Err(err) => {
                log::error!("Error building {}: {err}", self.name);
                None
            }
        }
    }
}

pub fn bitstream_download(manifest_path: String) -> Result<(), anyhow::Error> {
    let out_path = bitstream_downloader::download_bitstream(Path::new(manifest_path.as_str()))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = out_path
        .to_str()
        .ok_or_else(|| anyhow!("invalid output file path"))?;
    log::info!("Download path bitstream: {}", out);
    Ok(())
}

pub fn prepare_artifact(path: &str, out_dir: &str) -> Result<(), anyhow::Error> {
    let path = Path::new(path);
    let out_dir = Path::new(out_dir);

    std::fs::create_dir_all(out_dir)?;

    let file_name = path.file_name().ok_or_else(|| anyhow!("Invalid path"))?;
    let zip_name = format!("{}.zip", file_name.to_str().unwrap());
    let zip_path = out_dir.join(&zip_name);

    let file = std::fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

    if path.is_dir() {
        add_directory_to_zip(&mut zip, path, "", options)?;
    } else {
        add_file_to_zip(&mut zip, path, file_name.to_str().unwrap(), options)?;
    }

    zip.finish()?;

    let mut file = std::fs::File::open(&zip_path)?;
    let mut hasher = sha2::Sha384::new();
    std::io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    let hash_str = hex::encode(hash);

    let hash_path = out_dir.join(format!("{}.sha384", zip_name));
    std::fs::write(hash_path, format!("{}  {}\n", hash_str, zip_name))?;

    Ok(())
}

fn add_file_to_zip<W: std::io::Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    path: &Path,
    name: &str,
    options: FileOptions,
) -> Result<(), anyhow::Error> {
    zip.start_file(name, options)?;
    let mut f = std::fs::File::open(path)?;
    std::io::copy(&mut f, zip)?;
    Ok(())
}

fn add_directory_to_zip<W: std::io::Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    path: &Path,
    base_path: &str,
    options: FileOptions,
) -> Result<(), anyhow::Error> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_str().unwrap();
        let full_name = if base_path.is_empty() {
            name_str.to_string()
        } else {
            format!("{}/{}", base_path, name_str)
        };

        if path.is_dir() {
            zip.add_directory(&full_name, options)?;
            add_directory_to_zip(zip, &path, &full_name, options)?;
        } else {
            add_file_to_zip(zip, &path, &full_name, options)?;
        }
    }
    Ok(())
}

fn build_octocrab() -> Result<octocrab::Octocrab, anyhow::Error> {
    let mut builder = octocrab::Octocrab::builder();
    let token = std::env::var("GITHUB_TOKEN").map_err(|_| anyhow!("GITHUB_TOKEN not set"))?;
    builder = builder.personal_token(token);
    Ok(builder.build()?)
}

pub fn download_artifact(
    run_id: &str,
    name: &str,
    dest_dir: &str,
    hash_file: &str,
    retries: u32,
) -> Result<(), anyhow::Error> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async { download_artifact_async(run_id, name, dest_dir, hash_file, retries).await })
}

async fn download_artifact_async(
    run_id: &str,
    name: &str,
    dest_dir: &str,
    hash_file: &str,
    retries: u32,
) -> Result<(), anyhow::Error> {
    let crab = build_octocrab()?;
    let dest_dir = Path::new(dest_dir);

    let url = format!(
        "/repos/chipsalliance/caliptra-sw/actions/runs/{}/artifacts",
        run_id
    );
    let response: serde_json::Value = crab.get(&url, None::<&()>).await?;
    let artifacts = response["artifacts"]
        .as_array()
        .ok_or_else(|| anyhow!("Invalid response"))?;
    if name.is_empty() {
        for artifact in artifacts {
            let art_name = artifact["name"].as_str().unwrap();
            let art_id = artifact["id"].as_u64().unwrap();
            let art_dest_dir = dest_dir.join(art_name);
            download_single_artifact(art_id, art_name, &art_dest_dir, "", retries).await?;
        }
        return Ok(());
    }

    let artifact = artifacts
        .iter()
        .find(|a| a["name"] == name)
        .ok_or_else(|| anyhow!("Artifact not found"))?;
    let artifact_id = artifact["id"]
        .as_u64()
        .ok_or_else(|| anyhow!("Invalid artifact ID"))?;

    download_single_artifact(artifact_id, name, dest_dir, hash_file, retries).await
}

async fn download_single_artifact(
    artifact_id: u64,
    name: &str,
    dest_dir: &Path,
    hash_file: &str,
    retries: u32,
) -> Result<(), anyhow::Error> {
    let download_url = format!(
        "/repos/chipsalliance/caliptra-sw/actions/artifacts/{}/zip",
        artifact_id
    );

    for i in 1..=retries {
        println!("Attempt {} to download artifact {}", i, name);

        let _ = std::fs::remove_dir_all(dest_dir);
        std::fs::create_dir_all(dest_dir)?;

        let token = std::env::var("GITHUB_TOKEN").map_err(|_| anyhow!("GITHUB_TOKEN not set"))?;

        let client = reqwest::Client::builder()
            .user_agent("caliptra-sw-xtask")
            .build()?;

        let response = client
            .get(format!("https://api.github.com{}", download_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?;

        if !response.status().is_success() {
            println!("Failed to download artifact: {}", response.status());
            std::thread::sleep(std::time::Duration::from_secs(5));
            continue;
        }

        let bytes = response.bytes().await?;

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        archive.extract(dest_dir)?;

        if hash_file.is_empty() {
            println!("Skipping hash verification for download all");
            return Ok(());
        }

        let output = std::process::Command::new("sha384sum")
            .arg("-c")
            .arg(hash_file)
            .current_dir(dest_dir)
            .output()?;

        if output.status.success() {
            println!("Hash matches!");
            return Ok(());
        } else {
            println!("Hash mismatch: {}", String::from_utf8_lossy(&output.stderr));
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }

    Err(anyhow!(
        "Failed to download and verify artifact {} after {} attempts",
        name,
        retries
    ))
}
