// Licensed under the Apache-2.0 license

//! A framework for tracking artifact sizes across git history.
//!
//! This crate provides traits and implementations for:
//! - Building artifacts and measuring their sizes ([`ArtifactBuilder`])
//! - Caching build results ([`Cache`])
//! - Generating reports ([`ReportGenerator`])
//! - Writing output to various destinations ([`OutputDestination`])
//!
//! # Example
//!
//! ```ignore
//! use caliptra_size_history::{
//!     ArtifactBuilder, CaliptraFirmwareBuilder, HtmlTableReport,
//!     OutputDestination, SizeTracker, Stdout,
//! };
//!
//! let builders: Vec<Box<dyn ArtifactBuilder>> = vec![
//!     Box::new(CaliptraFirmwareBuilder::new("ROM", firmware::ROM)),
//! ];
//!
//! // ... configure and run
//! ```

mod builder;
mod cache;
mod cache_gha;
pub mod git;
mod http;
mod output;
mod process;
mod report;
pub(crate) mod util;

use serde::{Deserialize, Serialize};

// Re-exports
pub use builder::{ArtifactBuilder, CaliptraFirmwareBuilder};
pub use cache::{Cache, FsCache};
pub use cache_gha::GithubActionCache;
pub use git::CommitInfo;
pub use output::{FileOutput, GitHubStepSummary, OutputDestination, Stdout};
pub use report::{HtmlTableReport, ReportGenerator};

/// Represents a built artifact with its name and measured size.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    /// Size in bytes. None if build failed.
    pub size: Option<u64>,
}

impl Artifact {
    pub fn new(name: impl Into<String>, size: Option<u64>) -> Self {
        Self {
            name: name.into(),
            size,
        }
    }
}

/// A record of artifact sizes for a specific commit.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SizeRecord {
    pub commit: git::CommitInfo,
    /// Artifact sizes in order.
    pub artifacts: Vec<Artifact>,
}

impl SizeRecord {
    /// Get the size for a specific artifact by name.
    pub fn get_size(&self, name: &str) -> Option<u64> {
        self.artifacts
            .iter()
            .find(|a| a.name == name)
            .and_then(|a| a.size)
    }
}
