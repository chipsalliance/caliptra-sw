// Licensed under the Apache-2.0 license

use std::{fs, io, path::PathBuf};

use crate::util::other_err;

pub trait OutputDestination {
    fn write(&self, content: &str) -> io::Result<()>;
}

pub struct GitHubStepSummary;

impl OutputDestination for GitHubStepSummary {
    fn write(&self, content: &str) -> io::Result<()> {
        let path = std::env::var("GITHUB_STEP_SUMMARY")
            .map_err(|_| other_err("GITHUB_STEP_SUMMARY environment variable not set"))?;
        fs::write(path, content)
    }
}

pub struct Stdout;

impl OutputDestination for Stdout {
    fn write(&self, content: &str) -> io::Result<()> {
        println!("{}", content);
        Ok(())
    }
}

pub struct FileOutput {
    pub path: PathBuf,
}

impl FileOutput {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl OutputDestination for FileOutput {
    fn write(&self, content: &str) -> io::Result<()> {
        fs::write(&self.path, content)
    }
}
