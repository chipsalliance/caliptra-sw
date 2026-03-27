// Licensed under the Apache-2.0 license

use std::{env, error::Error, path::Path};

use caliptra_builder::firmware;
use caliptra_size_history::{
    git, Artifact, ArtifactBuilder, Cache, CaliptraFirmwareBuilder, FsCache, GitHubStepSummary,
    GithubActionCache, HtmlTableReport, OutputDestination, ReportGenerator, SizeRecord, Stdout,
};

// Increment with non-backwards-compatible changes to cache record format
const CACHE_FORMAT_VERSION: &str = "v4";

fn main() -> Result<(), Box<dyn Error>> {
    // Configure artifact builders
    let builders: Vec<Box<dyn ArtifactBuilder>> = vec![
        Box::new(CaliptraFirmwareBuilder::new("ROM prod size", firmware::ROM)),
        Box::new(CaliptraFirmwareBuilder::new(
            "ROM with-uart size",
            firmware::ROM_WITH_UART,
        )),
        Box::new(CaliptraFirmwareBuilder::new(
            "FMC size",
            firmware::FMC_WITH_UART,
        )),
        Box::new(CaliptraFirmwareBuilder::new(
            "App size",
            firmware::APP_WITH_UART,
        )),
        Box::new(CaliptraFirmwareBuilder::new(
            "App with OCP LOCK size",
            firmware::APP_WITH_UART_OCP_LOCK,
        )),
    ];

    let reporter = HtmlTableReport::new("https://github.com/chipsalliance/caliptra-sw");
    let output: Box<dyn OutputDestination> = if env::var("GITHUB_STEP_SUMMARY").is_ok() {
        Box::new(GitHubStepSummary)
    } else {
        Box::new(Stdout)
    };

    let cache = create_cache()?;

    let worktree_path = Path::new("/tmp/caliptra-size-history-wt");
    let worktree = git::WorkTree::new(worktree_path)?;
    let head_commit = worktree.head_commit_id()?;

    handle_pr_history(&worktree, &head_commit)?;

    let git_commits = worktree.commit_log()?;
    env::set_current_dir(worktree_path)?;

    let mut records = vec![];
    let mut cached_commit = None;

    for commit in git_commits.iter() {
        match cache.get(&format_cache_key(&commit.id)) {
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

        let artifacts = compute_sizes(&builders, &worktree);
        records.push(SizeRecord {
            commit: commit.clone(),
            artifacts,
        });
    }

    for (i, record) in records.iter().enumerate() {
        if Some(&record.commit.id) == cached_commit.as_ref() {
            break;
        }
        if let Err(e) = cache.set(
            &format_cache_key(&record.commit.id),
            &serde_json::to_vec(&records[i..]).unwrap(),
        ) {
            println!(
                "Unable to write to cache for commit {}: {e}",
                record.commit.id
            );
        }
    }

    let artifact_names: Vec<&str> = builders.iter().map(|b| b.name()).collect();
    let report = reporter.generate(&records, &artifact_names)?;
    output.write(&report)?;

    Ok(())
}

fn create_cache() -> Result<Box<dyn Cache>, Box<dyn Error>> {
    Ok(GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?)
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

fn handle_pr_history(worktree: &git::WorkTree, head_commit: &str) -> Result<(), Box<dyn Error>> {
    let is_pr = env::var("EVENT_NAME").is_ok_and(|name| name == "pull_request")
        && env::var("PR_BASE_COMMIT").is_ok();

    if is_pr && !worktree.is_log_linear()? {
        println!("git history is not linear; attempting to squash PR");
        let (Ok(pull_request_title), Ok(base_ref)) =
            (env::var("PR_TITLE"), env::var("PR_BASE_COMMIT"))
        else {
            return Err("cannot attempt squash outside of a PR".into());
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

fn compute_sizes(builders: &[Box<dyn ArtifactBuilder>], worktree: &git::WorkTree) -> Vec<Artifact> {
    builders
        .iter()
        .map(|builder| {
            let size = builder.build_and_measure(worktree.path);
            Artifact::new(builder.name(), size)
        })
        .collect()
}

fn format_cache_key(commit: &str) -> String {
    format!("{}-{}", CACHE_FORMAT_VERSION, commit)
}
