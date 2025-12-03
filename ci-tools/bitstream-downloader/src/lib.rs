// Licensed under the Apache-2.0 license

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct Bitstream {
    pub name: String,
    pub url: String,
    pub hash: String,
    pub caliptra_variant: String,
}

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub bitstream: Bitstream,
}

pub fn download_bitstream(manifest_path: &Path) -> Result<PathBuf> {
    let manifest_content = fs::read_to_string(manifest_path)
        .context("failed to read manifest file")?;
    let manifest: Manifest = toml::from_str(&manifest_content)
        .context("failed to parse manifest TOML")?;

    println!("Downloading bitstream: {}", manifest.bitstream.name);
    println!("URL: {}", manifest.bitstream.url);

    let response = reqwest::blocking::get(&manifest.bitstream.url)
        .context("failed to make request")?;
    let mut content = io::Cursor::new(response.bytes().context("failed to read response bytes")?);

    let mut hasher = Sha256::new();
    io::copy(&mut content, &mut hasher).context("failed to read content for hashing")?;
    let calculated_hash = hasher.finalize();
    let calculated_hash_hex = hex::encode(calculated_hash);

    println!("Expected hash: {}", manifest.bitstream.hash);
    println!("Calculated hash: {}", calculated_hash_hex);

    if calculated_hash_hex == manifest.bitstream.hash {
        println!("Hash verification successful!");
    } else {
        bail!(
            "hash mismatch expected: {}, got: {}",
            manifest.bitstream.hash,
            calculated_hash_hex
        );
    }
    let output_filename = format!("{}.pdi", manifest.bitstream.caliptra_variant);
    let output_path = PathBuf::from(&output_filename);
    let mut file = fs::File::create(&output_path).context("failed to create output file")?;
    content.set_position(0);
    io::copy(&mut content, &mut file).context("failed to write output file")?;
    println!("PDI saved to: {}", output_filename);
    Ok(output_path)
}
