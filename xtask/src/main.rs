// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use std::path::Path;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run CI tools
    #[clap(name = "ci")]
    CI {
        #[clap(subcommand)]
        command: CICommands,
    },
}

#[derive(Subcommand)]
enum CICommands {
    /// Run the bitstream downloader tool.
    #[clap(name = "bitstream-downloader")]
    BitstreamDownloader { path: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CI { command } => match command {
            CICommands::BitstreamDownloader { path } => {
                println!("Downloading bitstream using manifest: {}", path);
                bitstream_downloader::download_bitstream(Path::new(&path)).await?;
                println!("Download complete!");
            }
        },
    }
    Ok(())
}
