// Licensed under the Apache-2.0 license

use std::{io, path::Path, process::Command};

use serde::{Deserialize, Serialize};

use crate::{
    process::{run_cmd, run_cmd_stdout},
    util::{bytes_to_string, expect_line, expect_line_with_prefix, other_err},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitInfo {
    pub id: String,
    pub author: String,
    pub title: String,
}
impl CommitInfo {
    fn parse_multiple(s: &str) -> io::Result<Vec<CommitInfo>> {
        let mut lines = s.lines();
        let mut result = vec![];
        'outer: loop {
            let Some(line) = lines.next() else {
                break;
            };
            let commit_id = expect_line_with_prefix("commit ", Some(line))?;
            let author = expect_line_with_prefix("Author: ", lines.next())?;
            expect_line("", lines.next())?;
            let mut title = expect_line_with_prefix("    ", lines.next())?.to_string();
            'inner: loop {
                let Some(line) = lines.next() else {
                    result.push(CommitInfo{
                        id: commit_id.into(),
                        author: author.into(),
                        title,
                    });
                    break 'outer;
                };
                if line.is_empty() {
                    break 'inner;
                }
                title.push('\n');
                title.push_str(expect_line_with_prefix("    ", Some(line))?);
            }
            result.push(CommitInfo {
                id: commit_id.into(),
                author: author.into(),
                title,
            });
        }
        Ok(result)
    }
}

fn to_utf8(bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|_| other_err("git output is not utf-8"))
}

pub struct WorkTree<'a> {
    pub path: &'a Path,
}
impl<'a> WorkTree<'a> {
    pub fn new(path: &'a Path) -> io::Result<Self> {
        run_cmd(
            Command::new("git")
                .arg("worktree")
                .arg("add")
                .arg(path)
                .arg("HEAD"),
        )?;
        Ok(Self { path })
    }

    pub fn is_log_linear(&self) -> io::Result<bool> {
        let stdout = to_utf8(run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("rev-list")
                .arg("--min-parents=2")
                .arg("--count")
                .arg("HEAD"),
            None,
        )?)?;
        Ok(stdout.trim() == "0")
    }

    pub fn commit_log(&self) -> io::Result<Vec<CommitInfo>> {
        CommitInfo::parse_multiple(&bytes_to_string(run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("log")
                .arg("--pretty=short")
                .arg("--decorate=no"),
            None,
        )?)?)
    }

    pub fn checkout(&self, commit_id: &str) -> io::Result<()> {
        run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("checkout")
                .arg("--no-recurse-submodule")
                .arg("--quiet")
                .arg(commit_id),
            None,
        )?;
        Ok(())
    }
    pub fn submodule_update(&self) -> io::Result<()> {
        run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("submodule")
                .arg("update"),
            None,
        )?;
        Ok(())
    }
    pub fn head_commit_id(&self) -> io::Result<String> {
        Ok(to_utf8(run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("rev-parse")
                .arg("HEAD"),
            None,
        )?)?
        .trim()
        .into())
    }
    pub fn reset_hard(&self, commit_id: &str) -> io::Result<()> {
        run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("reset")
                .arg("--hard")
                .arg(commit_id),
            None,
        )?;
        Ok(())
    }
    pub fn set_fs_contents(&self, commit_id: &str) -> io::Result<()> {
        run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("checkout")
                .arg(commit_id)
                .arg("--")
                .arg("."),
            None,
        )?;
        Ok(())
    }
    pub fn commit(&self, message: &str) -> io::Result<()> {
        run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("commit")
                .arg("-a")
                .arg("-m")
                .arg(message),
            None,
        )?;
        Ok(())
    }
    pub fn is_ancestor(&self, possible_ancestor: &str, commit: &str) -> io::Result<bool> {
        Ok(Command::new("git")
            .current_dir(self.path)
            .arg("merge-base")
            .arg("--is-ancestor")
            .arg(possible_ancestor)
            .arg(commit)
            .status()?
            .code()
            == Some(0))
    }
    pub fn merge_log(&self) -> io::Result<Vec<Vec<String>>> {
        let stdout = to_utf8(run_cmd_stdout(
            Command::new("git")
                .current_dir(self.path)
                .arg("log")
                .arg("--merges")
                .arg("--pretty=%P"),
            None,
        )?)?;
        let mut result = vec![];
        for line in stdout.lines() {
            let parents: Vec<String> = line.split(' ').map(|s| s.to_string()).collect();
            if !parents.is_empty() {
                result.push(parents);
            }
        }
        Ok(result)
    }
}
impl Drop for WorkTree<'_> {
    fn drop(&mut self) {
        let _ = run_cmd(
            Command::new("git")
                .arg("worktree")
                .arg("remove")
                .arg(self.path),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_info_parse() {
        let text = r#"commit e1b1e3c566b6bd7cdef0310dc88480034f0aa29f
Author: Vishal Mhatre <38512878+mhatrevi@users.noreply.github.com>

    [fix] Vendor signature should not include owner signed data (#319)

commit bd306c4809f54426a357ff01507ef660291e2b91
Author: Kor Nielsen <kor@google.com>

    Remove RUSTFLAGS from legacy ROM makefile. (#318)
    Multiline title
"#;
        assert_eq!(
            CommitInfo::parse_multiple(text).unwrap(),
            vec![
                CommitInfo {
                    id: "e1b1e3c566b6bd7cdef0310dc88480034f0aa29f".into(),
                    author: "Vishal Mhatre <38512878+mhatrevi@users.noreply.github.com>".into(),
                    title: "[fix] Vendor signature should not include owner signed data (#319)"
                        .into()
                },
                CommitInfo {
                    id: "bd306c4809f54426a357ff01507ef660291e2b91".into(),
                    author: "Kor Nielsen <kor@google.com>".into(),
                    title: "Remove RUSTFLAGS from legacy ROM makefile. (#318)\nMultiline title"
                        .into()
                }
            ]
        );
    }
}
