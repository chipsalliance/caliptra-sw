// Licensed under the Apache-2.0 license

use anyhow::{anyhow, bail, Context, Error, Result};
use log::info;
use std::fs;
use std::str::FromStr;

use crate::PROJECT_ROOT;

pub async fn release_checklist(tag_str: &str) -> Result<()> {
    let tag: ReleaseTag = tag_str.parse()?;

    info!(
        "Verifying version for {} to be {}.{}.{}\n",
        tag.component, tag.major, tag.minor, tag.patch
    );

    let release_files = ReleaseRelevantFiles::new()?;
    match tag.component.as_str() {
        "rom" => {
            check_rom(&tag, &release_files)?;
        }
        "fmc" => {
            check_fmc(&tag, &release_files)?;
        }
        "fw" => {
            check_fw(&tag, &release_files)?;
        }
        _ => bail!(
            "Unknown component '{}'. Expected 'rom', 'fmc', or 'rt'",
            tag.component
        ),
    }

    check_changelog(&tag.release_name())?;
    check_frozen_images()?;

    let meta = GitHubReleaseManager::new(&tag)?;
    check_nightly_workflow(&meta).await?;

    info!("All checks passed for {}!\n", tag.release_name());
    Ok(())
}

async fn deploy_async(tag_str: &str) -> Result<()> {
    release_checklist(tag_str).await?;

    let tag: ReleaseTag = tag_str.parse()?;
    let release_name = tag.release_name();

    info!("Creating git tag: {}", release_name);
    let tag_status = std::process::Command::new("git")
        .args(["tag", &release_name])
        .status()?;

    if !tag_status.success() {
        bail!("Failed to create git tag '{}'", release_name);
    }

    info!("Pushing git tag to release-repo: {}", release_name);
    let push_status = std::process::Command::new("git")
        .args(["push", "release-repo", &release_name])
        .status()?;

    if !push_status.success() {
        bail!("Failed to push git tag '{}' to release-repo", release_name);
    }

    info!("Successfully deployed tag {}", tag_str);

    let meta = GitHubReleaseManager::new(&tag)?;
    create_github_release(&meta).await?;

    Ok(())
}

#[derive(Clone, Debug)]
struct ReleaseTag {
    component: String,
    major: u32,
    minor: u32,
    patch: u32,
    rc: Option<u32>,
}

impl ReleaseTag {
    fn release_name(&self) -> String {
        if let Some(rc) = self.rc {
            format!(
                "{}-{}.{}.{}rc{}",
                self.component, self.major, self.minor, self.patch, rc
            )
        } else {
            format!(
                "{}-{}.{}.{}",
                self.component, self.major, self.minor, self.patch
            )
        }
    }
}

impl FromStr for ReleaseTag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            bail!("Invalid tag format. Expected component-major.minor.patch (e.g., fmc-1.2.3)");
        }
        let component = parts[0].to_string();
        let version = parts[1];
        let version_parts: Vec<&str> = version.split('.').collect();
        if version_parts.len() != 3 {
            bail!("Invalid version format. Expected major.minor.patch (e.g., 1.2.3)");
        }
        let major: u32 = version_parts[0].parse()?;
        let minor: u32 = version_parts[1].parse()?;

        let patch_part = version_parts[2];
        let (patch, rc) = if let Some((p, r)) = patch_part.split_once("rc") {
            (p.parse()?, Some(r.parse()?))
        } else {
            (patch_part.parse()?, None)
        };

        Ok(ReleaseTag {
            component,
            major,
            minor,
            patch,
            rc,
        })
    }
}

struct ReleaseRelevantFiles {
    version_rs: String,
    common_rs: String,
    default_images_toml: String,
    rom_readme: String,
    fmc_readme: String,
    fw_readme: String,
}

impl ReleaseRelevantFiles {
    fn new() -> Result<Self> {
        let version_rs = fs::read_to_string(PROJECT_ROOT.join("builder/src/version.rs"))?;
        let common_rs =
            fs::read_to_string(PROJECT_ROOT.join("test/tests/fips_test_suite/common.rs"))?;
        let toml =
            fs::read_to_string(PROJECT_ROOT.join("builder/test_data/default_image_options.toml"))?;
        let rom_readme = fs::read_to_string(PROJECT_ROOT.join("rom/dev/README.md"))?;
        let fmc_readme = fs::read_to_string(PROJECT_ROOT.join("fmc/README.md"))?;
        let fw_readme = fs::read_to_string(PROJECT_ROOT.join("runtime/README.md"))?;
        Ok(Self {
            version_rs,
            common_rs,
            default_images_toml: toml,
            rom_readme,
            fmc_readme,
            fw_readme,
        })
    }
}

fn verify_common(
    tag: &ReleaseTag,
    files: &ReleaseRelevantFiles,
    version_prefix: &str,
    version_type: &str,
    readme: &str,
) -> Result<()> {
    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    if !files.version_rs.contains(&format!(
        "pub const {}_VERSION_MAJOR: {} = {};",
        version_prefix, version_type, major
    )) || !files.version_rs.contains(&format!(
        "pub const {}_VERSION_MINOR: {} = {};",
        version_prefix, version_type, minor
    )) || !files.version_rs.contains(&format!(
        "pub const {}_VERSION_PATCH: {} = {};",
        version_prefix, version_type, patch
    )) {
        bail!(
            "builder/src/version.rs does not have correct {} version",
            version_prefix
        );
    }

    if !readme.contains(&format!("v{}.{}", major, minor)) {
        bail!(
            "{} README does not contain expected version v{}.{}",
            tag.component,
            major,
            minor
        );
    }
    Ok(())
}

fn check_rom(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "ROM", "u16", &files.rom_readme)?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let rom_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", rom_hex);
    if !files.common_rs.contains(&expected_hex) {
        bail!(
            "test/tests/fips_test_suite/common.rs does not contain expected ROM hex version {}",
            expected_hex
        );
    }

    info!("rom version check passed!");

    Ok(())
}

fn check_fmc(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "FMC", "u16", &files.fmc_readme)?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let fmc_hex = ((major & 0x1F) << 11) | ((minor & 0x1F) << 6) | (patch & 0x3F);
    let expected_hex = format!("0x{:04x}", fmc_hex);

    if !files
        .default_images_toml
        .contains(&format!("fmc_version = {}", expected_hex))
    {
        bail!("builder/test_data/default_image_options.toml does not contain expected FMC hex version {}", expected_hex);
    }

    if !files.common_rs.contains(&expected_hex) {
        bail!(
            "test/tests/fips_test_suite/common.rs does not contain expected FMC hex version {}",
            expected_hex
        );
    }

    info!("fmc version check passed!");

    Ok(())
}

fn check_fw(tag: &ReleaseTag, files: &ReleaseRelevantFiles) -> Result<()> {
    verify_common(tag, files, "RUNTIME", "u32", &files.fw_readme)?;

    let major = tag.major;
    let minor = tag.minor;
    let patch = tag.patch;

    let rt_hex = ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | (patch & 0xFFFF);

    if !files
        .default_images_toml
        .contains(&format!("app_version = 0x{:x}", rt_hex))
    {
        bail!("builder/test_data/default_image_options.toml does not contain expected FW hex version 0x{:x}", rt_hex);
    }

    let common_rs_clean = files.common_rs.replace("_", "");
    if !common_rs_clean.contains(&format!("0x{:08x}", rt_hex)) {
        bail!("test/tests/fips_test_suite/common.rs does not contain expected FW hex version 0x{:08x}", rt_hex);
    }

    info!("fw version check passed!");

    Ok(())
}

pub fn check_frozen_images() -> Result<()> {
    crate::update_frozen_images::check_frozen_images()?;
    Ok(())
}

#[derive(serde::Deserialize, Debug)]
struct WorkflowRuns {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(serde::Deserialize, Debug)]
struct WorkflowRun {
    conclusion: Option<String>,
}

struct GitHubReleaseManager {
    crab: octocrab::Octocrab,
    owner: String,
    repo: String,
    head_commit: String,
    tag: ReleaseTag,
    nightly_tag: String,
}

impl GitHubReleaseManager {
    fn new(tag: &ReleaseTag) -> Result<Self> {
        let head_commit = {
            let head_output = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()?;
            String::from_utf8_lossy(&head_output.stdout)
                .trim()
                .to_string()
        };
        let nightly_tag = {
            let head_output = std::process::Command::new("git")
                .args(["describe", "--tags", &head_commit])
                .output()?;
            String::from_utf8_lossy(&head_output.stdout)
                .trim()
                .to_string()
        };

        let crab = {
            let token =
                std::env::var("GITHUB_TOKEN").map_err(|_| anyhow!("Missing GITHUB_TOKEN"))?;
            let mut builder = octocrab::Octocrab::builder();
            builder = builder.personal_token(token);

            builder.build()?
        };

        let url = {
            let output = std::process::Command::new("git")
                .args(["remote", "get-url", "release-repo"])
                .output()?;
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };

        let (owner, repo) = if url.contains("github.com") {
            let path = url
                .split("github.com")
                .last()
                .unwrap()
                .trim_start_matches(&[':', '/'][..])
                .trim_end_matches(".git");
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() == 2 {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                ("chipsalliance".to_string(), "caliptra-sw".to_string())
            }
        } else {
            bail!("Unsupported forge: {url}");
        };

        Ok(GitHubReleaseManager {
            crab,
            owner,
            repo,
            head_commit,
            tag: tag.clone(),
            nightly_tag,
        })
    }
}

async fn check_nightly_workflow(meta: &GitHubReleaseManager) -> Result<()> {
    info!(
        "Checking if nightly release workflow passed for commit {}...",
        meta.head_commit
    );

    let url = format!(
        "/repos/{}/{}/actions/workflows/nightly-release.yml/runs?head_sha={}",
        meta.owner, meta.repo, meta.head_commit
    );
    let runs: WorkflowRuns = meta.crab.get(url, None::<&()>).await?;

    let run = runs.workflow_runs.into_iter().next().ok_or_else(|| {
        anyhow!(
            "No nightly workflow run found for commit {}",
            meta.head_commit
        )
    })?;

    let conclusion = run.conclusion.unwrap_or_else(|| "in_progress".to_string());
    if conclusion != "success" {
        bail!(
            "Nightly workflow for commit {} did not succeed (status: '{}'). Cannot deploy.",
            meta.head_commit,
            conclusion
        );
    }
    Ok(())
}

fn check_changelog(release_name: &str) -> Result<()> {
    let _ = extract_changelog(release_name)?;
    Ok(())
}

fn extract_changelog(release_name: &str) -> Result<String> {
    let content = std::fs::read_to_string(PROJECT_ROOT.join("CHANGELOG.md"))
        .context("Could not find CHANGELOG.md")?;
    let mut in_section = false;
    let mut section = String::new();

    for line in content.lines() {
        // Break loop once we read the whole section. There may be subsections so break on just one
        // '#'.
        if line.chars().filter(|&c| c == '#').count() == 1 {
            if in_section {
                break;
            }
            if line.contains(release_name) {
                in_section = true;
                continue;
            }
        } else if in_section {
            section.push_str(line);
            section.push('\n');
        }
    }

    let trimmed = section.trim();
    if trimmed.is_empty() {
        bail!("CHANGELOG.md is missing an entry for {release_name}!");
    }
    Ok(trimmed.to_string())
}

async fn create_github_release(meta: &GitHubReleaseManager) -> Result<()> {
    info!(
        "Searching for an existing GitHub release matching commit {}...",
        meta.head_commit
    );

    // Do we need to iterate through more than 100 releases? I doubt we
    // want to tag a job from that far back.
    let page = meta
        .crab
        .repos(&meta.owner, &meta.repo)
        .releases()
        .list()
        .per_page(100)
        .send()
        .await?;

    let found_release = page
        .items
        .iter()
        .find(|r| r.tag_name == meta.nightly_tag)
        .ok_or(anyhow!(
            "Could not find a release for {}. Did the commit pass a nightly?",
            meta.head_commit
        ))?;

    let release_name = meta.tag.release_name();
    let release_body = extract_changelog(&release_name)?;

    info!(
        "Updating existing GitHub release (ID: {})...",
        found_release.id
    );
    let release = meta
        .crab
        .repos(&meta.owner, &meta.repo)
        .releases()
        .update(found_release.id.0)
        .tag_name(&release_name)
        .name(&release_name)
        .body(&release_body)
        .draft(false)
        .prerelease(meta.tag.rc.is_some())
        .send()
        .await?;

    info!("Successfully created GitHub release: {}", release.html_url);
    Ok(())
}

pub fn check(tag_str: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(release_checklist(tag_str))
}

pub fn deploy(tag_str: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(deploy_async(tag_str))
}
