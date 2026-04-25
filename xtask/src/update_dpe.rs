// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use log::info;
use std::fs;
use std::process::Command;

use toml_edit::{value, DocumentMut};

const DPE_REPO_URL: &str = "https://github.com/chipsalliance/caliptra-dpe";

pub(crate) fn update_dpe(rev: &str) -> Result<()> {
    let hash = resolve_git_ref(DPE_REPO_URL, rev)?;
    info!("Updating DPE references to hash {}", hash);

    update_cargo_toml(&hash)?;
    update_go_mod(&hash)?;

    Ok(())
}

fn update_cargo_toml(hash: &str) -> Result<()> {
    let cargo_toml_path = crate::PROJECT_ROOT.join("Cargo.toml");
    let content = fs::read_to_string(&cargo_toml_path)
        .context(format!("Failed to read {:?}", cargo_toml_path))?;

    let mut doc = content
        .parse::<DocumentMut>()
        .context("Failed to parse Cargo.toml")?;

    let mut updated = false;

    if let Some(dependencies) = doc
        .get_mut("workspace")
        .and_then(|w| w.get_mut("dependencies"))
        .and_then(|d| d.as_table_like_mut())
    {
        for dep in [
            "caliptra-dpe",
            "caliptra-dpe-crypto",
            "caliptra-dpe-platform",
        ] {
            if let Some(item) = dependencies.get_mut(dep) {
                if let Some(table) = item.as_inline_table_mut() {
                    if table.get("git").and_then(|v| v.as_str()) == Some(DPE_REPO_URL)
                        && table.get("rev").and_then(|v| v.as_str()) != Some(hash)
                    {
                        table.insert("rev", value(hash).into_value().unwrap());
                        updated = true;
                    }
                }
            }
        }
    }

    if !updated {
        info!("Cargo.toml already has the correct DPE hash");
        return Ok(());
    }

    fs::write(&cargo_toml_path, doc.to_string())
        .context(format!("Failed to write {:?}", cargo_toml_path))?;
    info!("Updated Cargo.toml with new DPE hash");

    // Sync the lockfile
    info!("Updating Cargo.lock...");
    let status = Command::new("cargo")
        .current_dir(&*crate::PROJECT_ROOT)
        .args([
            "update",
            "-p",
            "caliptra-dpe",
            "-p",
            "caliptra-dpe-crypto",
            "-p",
            "caliptra-dpe-platform",
        ])
        .status()?;

    if !status.success() {
        bail!("Failed to run cargo update");
    }

    Ok(())
}

fn update_go_mod(hash: &str) -> Result<()> {
    let go_mod_path = crate::PROJECT_ROOT.join("test/dpe_verification/go.mod");
    if !go_mod_path.exists() {
        info!("test/dpe_verification/go.mod does not exist, skipping.");
        return Ok(());
    }

    info!("Updating test/dpe_verification/go.mod with new DPE hash");

    let go_dir = go_mod_path.parent().unwrap();

    // Update all DPE dependencies in one command
    let output = Command::new("go")
        .current_dir(go_dir)
        .arg("get")
        .arg(format!(
            "github.com/chipsalliance/caliptra-dpe/verification/sim@{}",
            hash
        ))
        .arg(format!(
            "github.com/chipsalliance/caliptra-dpe/verification/testing@{}",
            hash
        ))
        .arg(format!(
            "github.com/chipsalliance/caliptra-dpe/verification/client@{}",
            hash
        ))
        .output()?;

    if !output.status.success() {
        info!(
            "Note: Failed to update DPE dependencies in go.mod: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Tidy up the go.mod file
    let output = Command::new("go")
        .current_dir(go_dir)
        .args(["mod", "tidy"])
        .output()?;

    if !output.status.success() {
        bail!(
            "Failed to run go mod tidy: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

fn resolve_git_ref(repo_url: &str, rev: &str) -> Result<String> {
    // Check if the rev is already a 40-character hex string (likely a hash)
    if rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(rev.to_string());
    }

    info!("Resolving git revision '{}' for {}", rev, repo_url);

    let output = Command::new("git")
        .args(["ls-remote", repo_url, rev])
        .output()?;

    if !output.status.success() {
        bail!("Failed to run git ls-remote on {}", repo_url);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let hash = parts[0];
            let ref_name = parts[1];
            // If the reference is an exact match for the branch or tag
            if ref_name == format!("refs/heads/{}", rev)
                || ref_name == format!("refs/tags/{}", rev)
                || ref_name == rev
            {
                return Ok(hash.to_string());
            }
        }
    }

    // If it's still not found, it might be a shortened hash, but we really want a full hash for Cargo.toml
    bail!("Could not resolve git revision '{}' to a full hash", rev);
}
