// Licensed under the Apache-2.0 license

use std::{
    env::{self},
    fs, io,
    path::Path,
};

use caliptra_builder::{elf_size, firmware, FwId};
use serde::{Deserialize, Serialize};

mod cache;
mod cache_gha;
mod git;
mod html;
mod http;
mod process;
mod util;

use crate::cache::{Cache, FsCache};
use crate::{cache_gha::GithubActionCache, util::other_err};

// Increment with non-backwards-compatible changes are made to the cache record
// format
const CACHE_FORMAT_VERSION: &str = "v2";

#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Sizes {
    rom_size_with_uart: Option<u64>,
    rom_size_prod: Option<u64>,
    fmc_size_with_uart: Option<u64>,
    app_size_with_uart: Option<u64>,
}
impl Sizes {
    fn update_from(&mut self, other: &Sizes) {
        self.rom_size_with_uart = other.rom_size_with_uart.or(self.rom_size_with_uart);
        self.rom_size_prod = other.rom_size_prod.or(self.rom_size_prod);
        self.fmc_size_with_uart = other.fmc_size_with_uart.or(self.fmc_size_with_uart);
        self.app_size_with_uart = other.app_size_with_uart.or(self.app_size_with_uart);
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct SizeRecord {
    commit: git::CommitInfo,
    sizes: Sizes,
}

fn main() {
    if let Err(e) = real_main() {
        println!("Fatal Error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> io::Result<()> {
    let cache = GithubActionCache::new().map(box_cache).or_else(|e| {
        let fs_cache_path = "/tmp/caliptra-size-cache";
        println!(
            "Unable to create github action cache: {e}; using fs-cache instead at {fs_cache_path}"
        );
        FsCache::new(fs_cache_path.into()).map(box_cache)
    })?;

    let worktree = git::WorkTree::new(Path::new("/tmp/caliptra-size-history-wt"))?;
    let head_commit = worktree.head_commit_id()?;

    if !worktree.is_log_linear()? {
        println!("git history is not linear; attempting to squash PR");
        let (Ok(pull_request_title), Ok(base_ref)) = (env::var("PR_TITLE"), env::var("PR_BASE_COMMIT")) else {
            return Err(other_err("non-linear history not supported outside of a PR"));
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
        worktree.set_fs_contents(&head_commit)?;
        println!("Committing squashed commit {pull_request_title:?}");
        worktree.commit(&pull_request_title)?;

        if !worktree.is_log_linear()? {
            return Err(other_err("history still non-linear after squash; aborting"));
        }
    }

    let git_commits = worktree.commit_log()?;

    env::set_current_dir(worktree.path)?;

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
            "Building firmware at commit {}: {}",
            commit.id, commit.title
        );
        worktree.checkout(&commit.id)?;
        worktree.submodule_update()?;

        records.push(SizeRecord {
            commit: commit.clone(),
            sizes: compute_size(&worktree, &commit.id),
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

    let html = html::format_records(&records)?;

    if let Ok(file) = env::var("GITHUB_STEP_SUMMARY") {
        fs::write(file, &html)?;
    } else {
        println!("{html}");
    }

    Ok(())
}

fn compute_size(worktree: &git::WorkTree, commit_id: &str) -> Sizes {
    // TODO: consider using caliptra_builder from the same repo as the firmware
    let fwid_elf_size = |fwid: &FwId| -> io::Result<u64> {
        let workspace_dir = Some(worktree.path);
        let elf_bytes = caliptra_builder::build_firmware_elf_uncached(workspace_dir, fwid)?;
        elf_size(&elf_bytes)
    };
    let fwid_elf_size_or_none = |fwid: &FwId| -> Option<u64> {
        match fwid_elf_size(fwid) {
            Ok(result) => Some(result),
            Err(err) => {
                println!("Error building commit {}: {err}", commit_id);
                None
            }
        }
    };

    Sizes {
        rom_size_with_uart: fwid_elf_size_or_none(&firmware::ROM_WITH_UART),
        rom_size_prod: fwid_elf_size_or_none(&firmware::ROM),
        fmc_size_with_uart: fwid_elf_size_or_none(&firmware::FMC_WITH_UART),
        app_size_with_uart: fwid_elf_size_or_none(&firmware::APP_WITH_UART),
    }
}

fn box_cache(val: impl Cache + 'static) -> Box<dyn Cache> {
    Box::new(val)
}

fn format_cache_key(commit: &str) -> String {
    format!("{CACHE_FORMAT_VERSION}-{commit}")
}
