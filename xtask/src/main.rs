// Licensed under the Apache-2.0 license

use clap::{Parser, Subcommand};
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

mod cargo_lock;
mod ci;
mod clippy;
mod format;
mod fpga;
mod license;
mod precheckin;
mod release;
mod release_info;
mod update_dpe;
mod update_frozen_images;
mod util;
mod vertex_ai;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Xtask {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Suppress informational logging (set log level below info, e.g., warn)
    #[arg(short, long, global = true)]
    quiet: bool,
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
    /// Update the DPE references
    UpdateDpe {
        /// The git revision to update DPE to (tag, branch, or git hash)
        #[arg(short, long, default_value = "main")]
        rev: String,
    },
    /// Build ROM images and update the FROZEN_IMAGES.sha384sum file
    UpdateFrozenImages,

    /// FPGA commands
    Fpga {
        #[command(subcommand)]
        command: fpga::Fpga,
    },

    /// Run CI tools
    CI {
        #[command(subcommand)]
        command: CICommands,
    },

    /// Call Vertex AI prediction endpoints
    VertexAi {
        /// Google Cloud Project ID
        #[arg(short, long, default_value = "caliptra-github-ci")]
        project: String,
        /// Location/Region (e.g. us-central1)
        #[arg(short, long, default_value = "us-central1")]
        location: String,
        /// Model ID (e.g. gemini-3.5-flash)
        #[arg(short, long, default_value = "gemini-3.5-flash")]
        model: String,
        /// Prompt string to submit to the model
        prompt: String,
    },

    /// Diff against a target branch and use Vertex AI to generate a nextest filter expression
    NextestFilter {
        /// Google Cloud Project ID
        #[arg(short, long, default_value = "caliptra-github-ci")]
        project: String,
        /// Target git branch/ref to diff against (e.g. main)
        #[arg(short, long, default_value = "main")]
        branch: String,
        /// Cargo nextest profile to validate against and fall back to (e.g. nightly-ci)
        #[arg(short = 'n', long, default_value = "nightly-ci")]
        profile: String,
        /// Location/Region (e.g. us-central1)
        #[arg(short, long, default_value = "us-central1")]
        location: String,
        /// Model ID (e.g. gemini-3.5-flash)
        #[arg(short, long, default_value = "gemini-3.5-flash")]
        model: String,
    },
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
    /// Extract version/hash/commit/SVN info for published ROM/FW releases.
    Info {
        /// Release name (e.g. 'rom-2.1.1', 'fw-2.0.1'). When omitted, all
        /// releases in the built-in list are processed.
        release_name: Option<String>,
        /// Output as markdown tables.
        #[arg(long)]
        markdown: bool,
        /// Build from source for releases that lack pre-built assets.
        #[arg(long)]
        build: bool,
    },
}

#[derive(Subcommand)]
pub enum CICommands {
    /// Run size-history tool.
    SizeHistory,
    /// Run the bitstream downloader tool.
    BitstreamDownloader {
        path: String,
    },
    TestMatrix,
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
    } else if cli.quiet {
        LevelFilter::Warn
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
            ReleaseCommands::Info {
                release_name,
                markdown,
                build,
            } => release_info::run(release_name.as_deref(), *markdown, *build),
        },
        Commands::UpdateDpe { rev } => update_dpe::update_dpe(rev),
        Commands::UpdateFrozenImages => update_frozen_images::update_frozen_images(),
        Commands::Fpga { command } => fpga::fpga_entry(command),
        Commands::CI { command } => match command {
            CICommands::SizeHistory => ci::size_history(),
            CICommands::BitstreamDownloader { path } => ci::bitstream_download(path.clone()),
            CICommands::TestMatrix => Ok(()),
        },
        Commands::VertexAi {
            project,
            location,
            model,
            prompt,
        } => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to build tokio runtime");
            rt.block_on(vertex_ai::run_generate_content(
                project.as_str(),
                location,
                model,
                prompt,
            ))
        }
        Commands::NextestFilter {
            project,
            branch,
            profile,
            location,
            model,
        } => {
            let rt = tokio::runtime::Runtime::new().expect("Failed to build tokio runtime");
            rt.block_on(vertex_ai::run_generate_nextest_filter(
                project.as_str(),
                location,
                model,
                branch.as_str(),
                profile.as_str(),
            ))
        }
    };
    result.unwrap_or_else(|e| {
        log::error!("Error: {}", e);
        std::process::exit(1);
    });
}
