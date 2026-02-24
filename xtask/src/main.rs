// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

mod clippy;
mod precheckin;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    #[command(subcommand)]
    xtask: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run clippy on all targets
    Clippy,
    /// Run pre-check-in checks
    Precheckin,
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
    let _ = SimpleLogger::new().with_level(LevelFilter::Debug).init();
    let cli = Xtask::parse();
    let result = match &cli.xtask {
        Commands::Clippy => clippy::clippy(),
        Commands::Precheckin => precheckin::precheckin(),
    };
    result.unwrap_or_else(|e| {
        log::error!("Error: {}", e);
        std::process::exit(1);
    });
}
