// Licensed under the Apache-2.0 license

use std::fs;
use std::io;
use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the bitstream manifest
    #[arg(long = "bitstream-manifest", value_name = "FILE")]
    bitstream_manifest: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Bitstream {
    name: String,
    url: String,
    hash: String,
    caliptra_variant: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    bitstream: Bitstream,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let manifest_content = fs::read_to_string(&cli.bitstream_manifest)
        .map_err(|e| format!("failed to read manifest file: {}", e))?;
    let manifest: Manifest = toml::from_str(&manifest_content)
        .map_err(|e| format!("failed to parse manifest TOML: {}", e))?;

    println!("Downloading bitstream: {}", manifest.bitstream.name);
    println!("URL: {}", manifest.bitstream.url);

    let response = reqwest::blocking::get(&manifest.bitstream.url)?;
    let mut content = io::Cursor::new(response.bytes()?);

    let mut hasher = Sha256::new();
    io::copy(&mut content, &mut hasher)?;
    let calculated_hash = hasher.finalize();
    let calculated_hash_hex = hex::encode(calculated_hash);

    println!("Expected hash: {}", manifest.bitstream.hash);
    println!("Calculated hash: {}", calculated_hash_hex);

    if calculated_hash_hex == manifest.bitstream.hash {
        println!("Hash verification successful!");
    } else {
        return Err(format!(
            "hash mismatch expected: {}, got: {}",
            manifest.bitstream.hash, calculated_hash_hex
        )
        .into());
    }
    let output_filename = format!("{}.pdi", manifest.bitstream.caliptra_variant);
    let mut file = fs::File::create(&output_filename)?;
    content.set_position(0);
    io::copy(&mut content, &mut file)?;
    println!("PDI saved to: {}", output_filename);
    Ok(())
}
