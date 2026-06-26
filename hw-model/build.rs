// Licensed under the Apache-2.0 license

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

#[derive(Deserialize)]
struct OtpCtrlMmap {
    partitions: Vec<Partition>,
}

#[derive(Deserialize)]
struct Partition {
    name: String,
    #[serde(default)]
    sw_digest: bool,
    #[serde(default)]
    hw_digest: bool,
    #[serde(default)]
    zeroizable: bool,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    name: String,
    size: String,
}

#[derive(Deserialize)]
struct FusesHjson {
    #[serde(default)]
    fields: Vec<FuseField>,
}

#[derive(Deserialize)]
struct FuseField {
    name: String,
    otp_item: String,
    #[allow(dead_code)]
    #[serde(default)]
    bits: u32,
    #[allow(dead_code)]
    #[serde(default)]
    description: String,
    #[allow(dead_code)]
    #[serde(default)]
    partition: String,
}

fn main() {
    println!(
        "cargo:rustc-env=OPENOCD_SYSFSGPIO_ADAPTER_CFG=../../../hw/fpga/openocd_sysfsgpio_adapter.cfg"
    );
    println!("cargo:rustc-env=OPENOCD_TAP_CFG=../../../hw/fpga/openocd_ss.cfg");
    println!("cargo:rerun-if-env-changed=CALIPTRA_MCU_FUSES_HJSON");
    println!("cargo:rerun-if-env-changed=CALIPTRA_MCU_COMMIT");

    if env::var_os("CARGO_FEATURE_FPGA_SUBSYSTEM").is_some() {
        generate_otp_ctrl_mmap_offsets();
    }
}

fn generate_otp_ctrl_mmap_offsets() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo");
    let mmap_path = Path::new(&manifest_dir)
        .join("../hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson");
    println!("cargo:rerun-if-changed={}", mmap_path.display());

    let input = fs::read_to_string(&mmap_path).unwrap_or_else(|err| {
        panic!(
            "failed to read OTP controller memory map {}: {err}",
            mmap_path.display()
        )
    });
    let mmap: OtpCtrlMmap = deser_hjson::from_str(&input)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", mmap_path.display()));

    // Build a map from OTP item name → list of fuse field names from fuses.hjson.
    // These field names become additional offset constants aliasing the same OTP item offset.
    let fuse_aliases = build_fuse_aliases();

    let generated = otp_ctrl_mmap_offsets_rs(&mmap.partitions, &fuse_aliases);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is set by Cargo");
    fs::write(
        Path::new(&out_dir).join("otp_ctrl_mmap_offsets.rs"),
        generated,
    )
    .expect("failed to write generated OTP controller memory map offsets");
}

/// Build a map from OTP item name (uppercased) → vec of fuse field names
/// that should be emitted as alias constants.
fn build_fuse_aliases() -> HashMap<String, Vec<String>> {
    let fuses_input = if let Ok(fuses_path) = env::var("CALIPTRA_MCU_FUSES_HJSON") {
        println!("cargo:rerun-if-changed={fuses_path}");
        fs::read_to_string(&fuses_path)
            .unwrap_or_else(|err| panic!("failed to read MCU fuses.hjson {fuses_path}: {err}"))
    } else {
        let commit = env::var("CALIPTRA_MCU_COMMIT").unwrap_or_else(|_| mcu_commit_from_workflow());
        download_fuses_hjson(&commit)
    };

    let fuses: FusesHjson = deser_hjson::from_str(&fuses_input)
        .unwrap_or_else(|err| panic!("failed to parse fuses.hjson: {err}"));

    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    for field in &fuses.fields {
        let key = const_name(&field.otp_item);
        aliases
            .entry(key)
            .or_default()
            .push(const_name(&field.name));
    }
    aliases
}

/// Parse the default CALIPTRA_MCU_COMMIT from .github/workflows/fpga-subsystem.yml.
fn mcu_commit_from_workflow() -> String {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workflow_path = Path::new(&manifest_dir).join("../.github/workflows/fpga-subsystem.yml");
    let content = fs::read_to_string(&workflow_path).unwrap_or_else(|err| {
        panic!(
            "failed to read workflow file {}: {err}",
            workflow_path.display()
        )
    });
    // Look for: CALIPTRA_MCU_COMMIT: ${{ inputs.mcu-commit || '<sha>' }}
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("CALIPTRA_MCU_COMMIT:") {
            // Extract the SHA from between the last pair of single quotes.
            if let Some(start) = trimmed.rfind('\'') {
                let before = &trimmed[..start];
                if let Some(end) = before.rfind('\'') {
                    let sha = &before[end + 1..];
                    if !sha.is_empty() {
                        return sha.to_string();
                    }
                }
            }
        }
    }
    panic!(
        "could not find CALIPTRA_MCU_COMMIT default SHA in {}",
        workflow_path.display()
    )
}

/// Download fuses.hjson from GitHub at the given commit.
fn download_fuses_hjson(commit: &str) -> String {
    let url = format!(
        "https://raw.githubusercontent.com/chipsalliance/caliptra-mcu-sw/{commit}/hw/fuses.hjson"
    );
    let output = Command::new("curl")
        .args(["-sfL", &url])
        .output()
        .expect("failed to run curl to download fuses.hjson");
    if !output.status.success() {
        panic!(
            "curl failed to download {url}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("fuses.hjson is not valid UTF-8")
}

fn otp_ctrl_mmap_offsets_rs(
    partitions: &[Partition],
    fuse_aliases: &HashMap<String, Vec<String>>,
) -> String {
    let mut output = String::from(
        "// Licensed under the Apache-2.0 license\n\
         //\n\
         // @generated by hw-model/build.rs from hw/latest/caliptra-ss/src/fuse_ctrl/data/otp_ctrl_mmap.hjson.\n\
         // Do not edit by hand.\n\n",
    );
    let mut offset = 0usize;

    for partition in partitions {
        let partition_offset = offset;
        output.push_str(&format!(
            "pub(crate) const {}_OFFSET: usize = {:#05x};\n",
            const_name(&partition.name),
            partition_offset
        ));

        for item in &partition.items {
            let item_const = const_name(&item.name);
            output.push_str(&format!(
                "pub(crate) const {item_const}_OFFSET: usize = {offset:#05x};\n",
            ));

            // Emit alias constants for any fuses.hjson fields mapped to this OTP item.
            if let Some(aliases) = fuse_aliases.get(&item_const) {
                for alias in aliases {
                    output.push_str(&format!(
                        "pub(crate) const {alias}_OFFSET: usize = {offset:#05x};\n",
                    ));
                }
            }

            offset += item_size(item);
        }

        if partition.sw_digest || partition.hw_digest {
            offset = offset.next_multiple_of(8);
            offset += 8;
        }
        if partition.zeroizable {
            offset += 8;
        }

        output.push_str(&format!(
            "pub(crate) const {}_SIZE: usize = {:#05x};\n\n",
            const_name(&partition.name),
            offset - partition_offset
        ));
    }

    output.push_str(&format!(
        "pub(crate) const OTP_CTRL_MMAP_SIZE: usize = {offset:#05x};\n"
    ));
    output
}

fn item_size(item: &Item) -> usize {
    item.size.parse().unwrap_or_else(|err| {
        panic!(
            "invalid OTP item size {:?} for {}: {err}",
            item.size, item.name
        )
    })
}

fn const_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}
