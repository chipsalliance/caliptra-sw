// Licensed under the Apache-2.0 license

use std::{env, error::Error, io, path::Path};

use anyhow::{anyhow, ensure, Context};
use caliptra_builder::{elf_size, firmware, FwId};
use size_history::{
    ArtifactBuilder, Cache, FsCache, GitHubStepSummary, GithubActionCache, HtmlTableReport,
    OutputDestination, SizeHistory, Stdout,
};

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
    let rt = tokio::runtime::Runtime::new()?;
    let out_path = rt
        .block_on(bitstream_downloader::download_bitstream(Path::new(
            manifest_path.as_str(),
        )))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let out = out_path
        .to_str()
        .ok_or_else(|| anyhow!("invalid output file path"))?;
    log::info!("Download path bitstream: {}", out);
    Ok(())
}

pub fn check_bitstream(path: &str, variant: &str) -> anyhow::Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read bitstream manifest {path}"))?;
    let manifest = bitstream_downloader::Manifest::from_toml(&content)?;
    validate_bitstream(&manifest, variant)?;
    log::info!(
        "Validated HW {} {} bitstream from {} (RTL {:?}), PDI {:?}",
        manifest.hw_major_version,
        manifest.caliptra_variant,
        manifest.commit_hash,
        manifest.caliptra_ss_commit,
        manifest.pdi_url,
    );
    Ok(())
}

fn validate_bitstream(
    manifest: &bitstream_downloader::Manifest,
    variant: &str,
) -> anyhow::Result<()> {
    // (repository, branch, published variant name) of accepted 2.2 builders.
    // caliptra-infra builds both flavors; keep the legacy in-repo core builder
    // until the core manifest has moved.
    let sources: &[(&str, &str, &str)] = match variant {
        "core" => &[
            ("chipsalliance/caliptra-sw", "caliptra-2.2-dev", "core"),
            ("chipsalliance/caliptra-infra", "main", "core-2.2-segmented"),
        ],
        "subsystem" => &[(
            "chipsalliance/caliptra-infra",
            "main",
            "subsystem-2.2-segmented",
        )],
        _ => anyhow::bail!("Unsupported FPGA variant: {variant}"),
    };
    ensure!(
        manifest.hw_major_version == "2.2"
            && sources.iter().any(|(repository, branch, name)| {
                manifest.repository == *repository
                    && manifest.target_branch == *branch
                    && manifest.caliptra_variant == *name
            }),
        "Expected a HW 2.2 {variant} manifest from one of {sources:?}"
    );
    ensure!(
        manifest.segmented,
        "FPGA tests require a segmented bitstream"
    );
    let published_prefix = format!(
        "https://storage.googleapis.com/caliptra-github-ci-bitstreams/v1/{}/",
        manifest.commit_hash
    );
    ensure!(
        manifest
            .pdi_url
            .as_deref()
            .is_some_and(|url| url.starts_with(&published_prefix)),
        "Bitstream manifest requires a PDI URL under {published_prefix}"
    );
    ensure!(
        manifest.pdi_hash.as_deref().is_some_and(|hash| {
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
        "Bitstream manifest requires a SHA-256 PDI hash"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_manifest() -> bitstream_downloader::Manifest {
        bitstream_downloader::Manifest::from_toml(include_str!(
            "../../hw/fpga/bitstream_manifests/core.toml"
        ))
        .unwrap()
    }

    #[test]
    fn accepts_published_2_2_manifests() {
        validate_bitstream(&core_manifest(), "core").unwrap();
        let subsystem = bitstream_downloader::Manifest::from_toml(include_str!(
            "../../hw/fpga/bitstream_manifests/subsystem.toml"
        ))
        .unwrap();
        validate_bitstream(&subsystem, "subsystem").unwrap();
    }

    #[test]
    fn rejects_wrong_hardware_variant_or_source() {
        let mut manifest = core_manifest();
        manifest.hw_major_version = "2.1".into();
        assert!(validate_bitstream(&manifest, "core").is_err());
        assert!(validate_bitstream(&core_manifest(), "subsystem").is_err());
        let mut manifest = core_manifest();
        manifest.target_branch = "main".into();
        assert!(validate_bitstream(&manifest, "core").is_err());
    }

    #[test]
    fn accepts_caliptra_infra_manifests_for_matching_flavor() {
        let mut manifest = core_manifest();
        manifest.repository = "chipsalliance/caliptra-infra".into();
        manifest.target_branch = "main".into();
        manifest.caliptra_variant = "core-2.2-segmented".into();
        validate_bitstream(&manifest, "core").unwrap();
        assert!(validate_bitstream(&manifest, "subsystem").is_err());
        manifest.caliptra_variant = "subsystem-2.2-segmented".into();
        validate_bitstream(&manifest, "subsystem").unwrap();
        assert!(validate_bitstream(&manifest, "core").is_err());
        manifest.caliptra_variant = "subsystem-2.1-segmented".into();
        assert!(validate_bitstream(&manifest, "subsystem").is_err());
    }

    #[test]
    fn rejects_non_runtime_or_unpublished_manifests() {
        let mut manifest = core_manifest();
        manifest.segmented = false;
        assert!(validate_bitstream(&manifest, "core").is_err());
        let mut manifest = core_manifest();
        manifest.pdi_url = None;
        assert!(validate_bitstream(&manifest, "core").is_err());
        let mut manifest = core_manifest();
        manifest.pdi_hash = Some("invalid".into());
        assert!(validate_bitstream(&manifest, "core").is_err());
        let mut manifest = core_manifest();
        manifest.pdi_url = Some("https://example.com/runtime.pdi".into());
        assert!(validate_bitstream(&manifest, "core").is_err());
        let mut manifest = core_manifest();
        manifest.commit_hash = "0".repeat(40);
        assert!(validate_bitstream(&manifest, "core").is_err());
    }
}
