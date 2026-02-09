// Licensed under the Apache-2.0 license

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
pub struct Cli {
    /// Name of Github Organization to query the CI results for, e.g. "chipsalliance"
    #[arg(long = "org", default_value = "chipsalliance")]
    pub gh_org: String,

    /// Name of Github Repository to query the CI results for, e.g. "caliptra-sw"
    #[arg(short, long = "repo", default_value = "caliptra-sw")]
    pub gh_repo: String,

    /// Github token to query the CI results for, e.g. $GITHUB_TOKEN
    #[arg(short = 't', long = "token")]
    pub gh_token: String,

    /// Github workflow file/ run id to query the CI restuls for, e.g. "nightly-release.yml".
    /// The file name is not a path to the local file, but the associated file in the github CI for a run.
    #[arg(short = 'w', long = "workflow", default_value = "nightly-release.yml")]
    pub gh_workflow: String,

    /// Path to output directory to store the emitted HTML files into, e.g. "/tmp/www"
    #[arg(short = 'o', long = "out", default_value = "/tmp/www")]
    pub www_out: String,
}
