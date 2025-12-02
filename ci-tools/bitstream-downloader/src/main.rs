// Licensed under the Apache-2.0 license

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the bitstream manifest
    #[arg(long = "bitstream-manifest", value_name = "FILE")]
    bitstream_manifest: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    caliptra_bitstream_downloader::download_bitstream(&cli.bitstream_manifest)?;
    Ok(())
}
