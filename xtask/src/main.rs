// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

mod cargo_lock;
mod clippy;
mod format;
mod license;
mod precheckin;
mod release;
mod update_frozen_images;
mod util;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    xtask: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run clippy on all targets
    Clippy,
    /// Run pre-check-in checks
    Precheckin,
    /// Execute the release process
    Release {
        #[command(subcommand)]
        command: ReleaseCommands,
    },
    /// Build ROM images and update the FROZEN_IMAGES.sha384sum file
    UpdateFrozenImages,
}

#[derive(Subcommand)]
pub enum ReleaseCommands {
    /// Dry run release for the given release tag
    Check {
        /// The release tag to verify, formatted as component-major.minor.patch (e.g. fmc-2.0.0)
        tag: String,
    },
    /// Deploy a given release tag
    Deploy {
        /// The release tag to deploy, formatted as component-major.minor.patch (e.g. fmc-2.0.0)
        tag: String,
    },
}

pub static PROJECT_ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
    let current_dir = std::env::current_dir().expect("Could not get current directory");
    option_env!("CARGO_MANIFEST_DIR")
        .map(|s| {
            let p = Path::new(&s);
            if p.exists() {
                p.parent()
                    .unwrap_or(current_dir.clone().as_path())
                    .to_path_buf()
            } else {
                current_dir.clone()
            }
        })
        .unwrap_or(current_dir)
});

fn main() {
    let cli = Xtask::parse();
    let level = if cli.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let _ = SimpleLogger::new().with_level(level).init();
    let result = match &cli.xtask {
        Commands::Clippy => clippy::clippy(),
        Commands::Precheckin => precheckin::precheckin(),
        Commands::Release { command } => match command {
            ReleaseCommands::Check { tag } => release::check(tag),
            ReleaseCommands::Deploy { tag } => release::deploy(tag),
        },
        Commands::UpdateFrozenImages => update_frozen_images::update_frozen_images(),
    };
    result.unwrap_or_else(|e| {
        log::error!("Error: {}", e);
        std::process::exit(1);
    });
}
