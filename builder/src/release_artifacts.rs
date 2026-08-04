// Licensed under the Apache-2.0 license

use std::io::{self, Cursor};
use std::path::PathBuf;

pub struct ReleaseArtifacts {
    pub cache_dir: PathBuf,
}

impl ReleaseArtifacts {
    pub fn get_file(&self, bin_name: &str) -> io::Result<Vec<u8>> {
        let file_path = self.cache_dir.join(bin_name);
        std::fs::read(&file_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Failed to read release binary {bin_name} from {file_path:?}: {e}"),
            )
        })
    }
}

/// Downloads and extracts release artifacts from a GitHub release ZIP URL using `reqwest` and `zip::ZipArchive::extract`.
/// Results are cached locally in the system temp directory under `caliptra_release_cache/{version_tag}`.
pub fn download_and_extract_release(
    version_tag: &str,
    url: &str,
) -> anyhow::Result<ReleaseArtifacts> {
    let cache_dir = std::env::temp_dir()
        .join("caliptra_release_cache")
        .join(version_tag);

    std::fs::create_dir_all(&cache_dir)?;

    let rom_path = cache_dir.join("caliptra-rom-with-log.bin");
    let fw_path = cache_dir.join("image-bundle-mldsa.bin");

    if !rom_path.exists() && !fw_path.exists() {
        let response = reqwest::blocking::get(url)?;
        if !response.status().is_success() {
            anyhow::bail!(
                "Failed to download release zip from {}: HTTP status {}",
                url,
                response.status()
            );
        }

        let bytes = response.bytes()?;
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
        archive.extract(&cache_dir)?;
    }

    Ok(ReleaseArtifacts { cache_dir })
}
