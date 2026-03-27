// Licensed under the Apache-2.0 license

mod builder;
mod cache;
mod cache_gha;
pub mod git;
mod http;
mod output;
mod process;
mod report;
pub(crate) mod util;

use std::{env, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

// Re-exports
pub use builder::{ArtifactBuilder, CaliptraFirmwareBuilder};
pub use cache::{Cache, FsCache};
pub use cache_gha::GithubActionCache;
pub use git::CommitInfo;
pub use output::{FileOutput, GitHubStepSummary, OutputDestination, Stdout};
pub use report::{HtmlTableReport, ReportGenerator};

#[derive(Debug)]
pub enum SizeHistoryError {
    Git(std::io::Error),
    Cache(std::io::Error),
    Report(std::io::Error),
    Output(std::io::Error),
    Serialization(serde_json::Error),
    InvalidPrContext(String),
}

impl fmt::Display for SizeHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizeHistoryError::Git(e) => write!(f, "Git error: {}", e),
            SizeHistoryError::Cache(e) => write!(f, "Cache error: {}", e),
            SizeHistoryError::Report(e) => write!(f, "Report generation error: {}", e),
            SizeHistoryError::Output(e) => write!(f, "Output error: {}", e),
            SizeHistoryError::Serialization(e) => write!(f, "Serialization error: {}", e),
            SizeHistoryError::InvalidPrContext(msg) => write!(f, "Invalid PR context: {}", msg),
        }
    }
}

impl std::error::Error for SizeHistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SizeHistoryError::Git(e) => Some(e),
            SizeHistoryError::Cache(e) => Some(e),
            SizeHistoryError::Report(e) => Some(e),
            SizeHistoryError::Output(e) => Some(e),
            SizeHistoryError::Serialization(e) => Some(e),
            SizeHistoryError::InvalidPrContext(_) => None,
        }
    }
}

impl From<std::io::Error> for SizeHistoryError {
    fn from(e: std::io::Error) -> Self {
        SizeHistoryError::Git(e)
    }
}

impl From<serde_json::Error> for SizeHistoryError {
    fn from(e: serde_json::Error) -> Self {
        SizeHistoryError::Serialization(e)
    }
}

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

pub struct SizeHistory<R, C>
where
    R: ReportGenerator,
    C: Cache,
{
    reporter: R,
    output: Box<dyn OutputDestination>,
    cache: C,
    builders: Vec<Box<dyn ArtifactBuilder>>,
    worktree_path: PathBuf,
    cache_version: String,
    pr_squash_enabled: bool,
}

impl<R, C> SizeHistory<R, C>
where
    R: ReportGenerator,
    C: Cache,
{
    /// Create a new SizeHistory instance with the given reporter, output, and cache.
    pub fn new(reporter: R, output: Box<dyn OutputDestination>, cache: C) -> Self {
        Self {
            reporter,
            output,
            cache,
            builders: vec![],
            worktree_path: PathBuf::from("/tmp/size-history-wt"),
            cache_version: "v1".into(),
            pr_squash_enabled: false,
        }
    }

    /// Set the path for the git worktree.
    pub fn worktree_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.worktree_path = path.into();
        self
    }

    pub fn cache_version(mut self, version: impl Into<String>) -> Self {
        self.cache_version = version.into();
        self
    }

    pub fn add_builder(mut self, builder: Box<dyn ArtifactBuilder>) -> Self {
        self.builders.push(builder);
        self
    }

    /// Enable or disable PR squashing for non-linear git history.
    ///
    /// When enabled, if the git history is non-linear (has merge commits),
    /// the tool will attempt to squash the PR commits. This requires
    /// GitHub Actions environment variables to be set.
    pub fn with_pr_squashing(mut self, enabled: bool) -> Self {
        self.pr_squash_enabled = enabled;
        self
    }

    /// Run the size history tracking.
    ///
    /// This will:
    /// 1. Create a git worktree
    /// 2. Optionally handle PR squashing (if enabled)
    /// 3. Iterate through commits, checking cache and building artifacts
    /// 4. Store results in cache
    /// 5. Generate and output the report
    pub fn run(&self) -> Result<(), SizeHistoryError> {
        let worktree = git::WorkTree::new(&self.worktree_path)?;
        let head_commit = worktree.head_commit_id()?;

        if self.pr_squash_enabled {
            self.handle_pr_history(&worktree, &head_commit)?;
        }

        let git_commits = worktree.commit_log()?;
        env::set_current_dir(&self.worktree_path)?;

        let mut records = vec![];
        let mut cached_commit = None;

        for commit in git_commits.iter() {
            match self.cache.get(&self.format_cache_key(&commit.id)) {
                Ok(Some(cached_records)) => {
                    if let Ok(cached_records) =
                        serde_json::from_slice::<Vec<SizeRecord>>(&cached_records)
                    {
                        println!("Found cache entry for remaining commits at {}", commit.id);
                        records.extend(cached_records);
                        cached_commit = Some(commit.id.clone());
                        break;
                    } else {
                        println!(
                            "Error parsing cache entry {:?}",
                            String::from_utf8_lossy(&cached_records)
                        );
                    }
                }
                Ok(None) => {} // not found
                Err(e) => println!("Error reading from cache: {e}"),
            }

            println!(
                "Building artifacts at commit {}: {}",
                commit.id, commit.title
            );
            worktree.checkout(&commit.id)?;
            worktree.submodule_update()?;

            let artifacts = self.compute_sizes(&worktree);
            records.push(SizeRecord {
                commit: commit.clone(),
                artifacts,
            });
        }

        // Store computed records in cache
        for (i, record) in records.iter().enumerate() {
            if Some(&record.commit.id) == cached_commit.as_ref() {
                break;
            }
            if let Err(e) = self.cache.set(
                &self.format_cache_key(&record.commit.id),
                &serde_json::to_vec(&records[i..])?,
            ) {
                println!(
                    "Unable to write to cache for commit {}: {e}",
                    record.commit.id
                );
            }
        }

        // Generate and output report
        let artifact_names: Vec<&str> = self.builders.iter().map(|b| b.name()).collect();
        let report = self
            .reporter
            .generate(&records, &artifact_names)
            .map_err(SizeHistoryError::Report)?;
        self.output
            .write(&report)
            .map_err(SizeHistoryError::Output)?;

        Ok(())
    }

    fn format_cache_key(&self, commit: &str) -> String {
        format!("{}-{}", self.cache_version, commit)
    }

    fn compute_sizes(&self, worktree: &git::WorkTree) -> Vec<Artifact> {
        self.builders
            .iter()
            .map(|builder| Artifact::new(builder.name(), builder.build_and_measure(worktree.path)))
            .collect()
    }

    fn handle_pr_history(
        &self,
        worktree: &git::WorkTree,
        head_commit: &str,
    ) -> Result<(), SizeHistoryError> {
        let is_pr = env::var("EVENT_NAME").is_ok_and(|name| name == "pull_request")
            && env::var("PR_BASE_COMMIT").is_ok();

        if is_pr && !worktree.is_log_linear()? {
            println!("git history is not linear; attempting to squash PR");
            let (Ok(pull_request_title), Ok(base_ref)) =
                (env::var("PR_TITLE"), env::var("PR_BASE_COMMIT"))
            else {
                return Err(SizeHistoryError::InvalidPrContext(
                    "cannot attempt squash outside of a PR".into(),
                ));
            };

            let mut rebase_onto: String = base_ref;
            for merge_parents in worktree.merge_log()? {
                for parent in merge_parents {
                    if worktree.is_ancestor(&parent, "remotes/origin/main")?
                        && !worktree.is_ancestor(&parent, &rebase_onto)?
                    {
                        println!(
                            "Found more recent merge from main; will rebase onto {}",
                            parent
                        );
                        rebase_onto = parent;
                    }
                }
            }

            println!("Resetting to {}", rebase_onto);
            worktree.reset_hard(&rebase_onto)?;
            println!("Set fs contents to {}", head_commit);
            worktree.set_fs_contents(head_commit)?;
            println!("Committing squashed commit {pull_request_title:?}");
            worktree.commit(&pull_request_title)?;
        }

        Ok(())
    }
}
