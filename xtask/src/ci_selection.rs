// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use std::{env, process::Command};

const ALL: [&str; 2] = ["latest", "2.1"];

fn select_revisions(paths: &[&str]) -> Vec<&'static str> {
    if paths.is_empty() {
        return ALL.to_vec();
    }

    let mut latest = false;
    let mut rev_21 = false;

    for path in paths {
        if path.starts_with("hw/rev-2_1/") {
            rev_21 = true;
        } else if path.starts_with("hw/latest/") {
            latest = true;
        } else {
            return ALL.to_vec();
        }
    }

    match (latest, rev_21) {
        (true, false) => vec!["latest"],
        (false, true) => vec!["2.1"],
        _ => ALL.to_vec(),
    }
}

fn git(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .output()
        .context("failed to execute git")?;

    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output.stdout)
}

fn git_text(args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(git(args)?)?.trim().to_owned())
}

fn changed_paths() -> Result<Vec<String>> {
    // pull_request checkout is GitHub's synthetic merge commit.
    let base = git_text(&["rev-parse", "HEAD^1"])?;
    let head = git_text(&["rev-parse", "HEAD^2"])?;
    let merge_base = git_text(&["merge-base", &base, &head])?;

    // Disabling rename detection includes both old and new paths.
    let diff = git(&[
        "diff",
        "--no-renames",
        "--name-only",
        "-z",
        &merge_base,
        &head,
    ])?;

    Ok(diff
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8_lossy(path).into_owned())
        .collect())
}

pub(crate) fn run() -> Result<()> {
    let revisions = if env::var("GITHUB_EVENT_NAME").as_deref() == Ok("pull_request") {
        let paths = changed_paths()?;
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        select_revisions(&paths)
    } else {
        ALL.to_vec()
    };

    println!("revisions={}", serde_json::to_string(&revisions)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_21() {
        assert_eq!(select_revisions(&["hw/rev-2_1/src/lib.rs"]), ["2.1"]);
    }

    #[test]
    fn only_latest() {
        assert_eq!(select_revisions(&["hw/latest/src/lib.rs"]), ["latest"]);
    }

    #[test]
    fn both_revisions() {
        assert_eq!(
            select_revisions(&["hw/latest/src/lib.rs", "hw/rev-2_1/src/lib.rs"]),
            ALL
        );
    }

    #[test]
    fn shared_firmware() {
        assert_eq!(select_revisions(&["rom/dev/src/main.rs"]), ALL);
    }

    #[test]
    fn workflow_change() {
        assert_eq!(select_revisions(&[".github/workflows/build-test.yml"]), ALL);
    }

    #[test]
    fn unknown_path() {
        assert_eq!(select_revisions(&["new-component/src/lib.rs"]), ALL);
    }

    #[test]
    fn empty_paths() {
        assert_eq!(select_revisions(&[]), ALL);
    }

    #[test]
    fn mixed_shared_and_revision() {
        assert_eq!(
            select_revisions(&["hw/rev-2_1/src/lib.rs", "drivers/src/lib.rs"]),
            ALL
        );
    }
}
