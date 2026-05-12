// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};

use std::path::Path;

use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::PROJECT_ROOT;

const BUILDER_IMAGE: &str = "ghcr.io/chipsalliance/caliptra-builder:latest";

/// Check that host system has all the tools that the xtask FPGA flows depends on.
pub fn check_host_dependencies() -> Result<()> {
    if Container::try_new().is_err() {
        bail!("Neither 'podman' nor 'docker' found on PATH. Please install one of them.");
    }
    let tools = [
        (
            "rsync --version",
            "'rsync' not found on PATH. Please install rsync.",
        ),
        (
            "cargo nextest --version",
            "'cargo-nextest' not found on PATH. Please install with `cargo install cargo-nextest`.",
        ),
    ];
    check_dependencies(None, &tools)
}

/// Check that FPGA  has all the tools that the xtask FPGA flows depends on.
pub fn check_fpga_dependencies(target_host: &str) -> Result<()> {
    let tools = [
        (
            "rsync --version",
            "'rsync' not found on FPGA PATH. Please install rsync on FPGA.",
        ),
        (
            "cargo-nextest --version",
            "'cargo-nextest' not found on FPGA PATH. Please install with `cargo install cargo-nextest` on FPGA.",
        ),
    ];
    check_dependencies(Some(target_host), &tools)
}

fn check_dependencies(target_host: Option<&str>, tools: &[(&str, &str)]) -> Result<()> {
    for (command, error_msg) in tools {
        if run_command_extended(RunCommandArgs {
            target_host,
            command,
            output: Output::Silence,
        })
        .is_err()
        {
            let error_msg = error_msg.to_string();
            bail!(error_msg);
        }
    }
    Ok(())
}

/// Copies a file to FPGA over rsync to the FPGA home folder.
pub fn rsync_file(target_host: &str, file: &str, dest_file: &str, from_fpga: bool) -> Result<()> {
    // TODO(clundin): We assume are files are dropped in the root / home folder. May want to find a
    // put things in their own directory.
    let copy = if from_fpga {
        format!("{target_host}:{file}")
    } else {
        format!("{target_host}:{dest_file}")
    };
    let args = if from_fpga {
        ["-avxz", &copy, "."]
    } else {
        ["-avxz", file, &copy]
    };
    let status = Command::new("rsync")
        .current_dir(&*PROJECT_ROOT)
        .args(args)
        .status()?;
    if !status.success() {
        bail!("failed rsync file: {file} to {target_host}");
    }
    Ok(())
}

/// Runs a command over SSH.
/// Captures output of command and returns it as a string
pub fn run_command_with_output(target_host: &str, command: &str) -> Result<String> {
    let res = run_command_extended(RunCommandArgs {
        target_host: Some(target_host),
        command,
        output: Output::Capture,
    })?;
    if let Some(output) = res {
        Ok(output)
    } else {
        bail!("Missing command output for command: '{command}'")
    }
}

/// Runs a command over SSH.
pub fn run_command(target_host: &str, command: &str) -> Result<()> {
    let _ = run_command_extended(RunCommandArgs {
        target_host: Some(target_host),
        command,
        ..Default::default()
    })?;
    Ok(())
}

/// Runs a command on the host.
pub fn run_command_host(command: &str) -> Result<()> {
    let _ = run_command_extended(RunCommandArgs {
        target_host: None,
        command,
        ..Default::default()
    })?;
    Ok(())
}

#[derive(Default, PartialEq)]
pub enum Output {
    Silence,
    Capture,
    #[default]
    Inherit,
}

#[derive(Default)]
pub struct RunCommandArgs<'a> {
    pub target_host: Option<&'a str>,
    pub command: &'a str,
    pub output: Output,
}

/// Runs a command over SSH.
/// Set `silence_output` to true to avoid outputting command logs.
pub fn run_command_extended(args: RunCommandArgs) -> Result<Option<String>> {
    let mut command = if let Some(target_host) = args.target_host {
        if args.output != Output::Silence {
            println!("[FPGA] Running command: {}", args.command);
        }
        let mut cmd = Command::new("ssh");
        cmd.current_dir(&*PROJECT_ROOT)
            .args([target_host, "-t", args.command]);
        cmd
    } else {
        if args.output != Output::Silence {
            println!("[HOST] Running command: {}", args.command);
        }
        let mut cmd = Command::new("sh");
        cmd.current_dir(&*PROJECT_ROOT).args(["-c", args.command]);
        cmd
    };

    match args.output {
        Output::Capture => {
            let output = command.output()?;
            Ok(Some(String::from_utf8(output.stdout)?))
        }
        Output::Silence => {
            let status = command
                .stdout(Stdio::null())
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if !status.success() {
                bail!("Failed to run command");
            }
            Ok(None)
        }
        Output::Inherit => {
            let status = command
                .stdout(Stdio::inherit())
                .stdin(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()?;
            if !status.success() {
                bail!("Failed to run command");
            }
            Ok(None)
        }
    }
}

pub struct NextestArchiveCommand {
    work_dir: String,
    features: Vec<String>,
    package_filter: Option<String>,
}

impl NextestArchiveCommand {
    pub fn new(work_dir: &str) -> Self {
        Self {
            work_dir: work_dir.into(),
            features: vec![],
            package_filter: None,
        }
    }

    #[allow(dead_code)]
    pub fn feature(mut self, feature: &str) -> Self {
        self.features.push(feature.into());
        self
    }

    pub fn features(mut self, features: &[&str]) -> Self {
        for f in features {
            self.features.push(f.to_string());
        }
        self
    }

    pub fn package_filter(mut self, filter: Option<&str>) -> Self {
        self.package_filter = filter.map(|s| s.into());
        self
    }

    pub fn build(self) -> String {
        let mut cmd = format!("cd {} && ", self.work_dir);
        cmd.push_str("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc ");
        cmd.push_str("cargo nextest archive ");

        if !self.features.is_empty() {
            cmd.push_str(&format!("--features={} ", self.features.join(",")));
        }

        if let Some(filter) = self.package_filter {
            cmd.push_str(&format!("-E '{}' ", filter));
        }

        cmd.push_str("--target=aarch64-unknown-linux-gnu ");
        cmd.push_str("--archive-file=/work-dir/caliptra-test-binaries.tar.zst ");
        cmd.push_str("--target-dir cross-target/");

        cmd
    }
}

pub struct Container {
    cmd: Command,
}

impl Container {
    pub fn try_new() -> Result<Self> {
        let program = if run_command_extended(RunCommandArgs {
            command: "podman --version",
            output: Output::Silence,
            ..Default::default()
        })
        .is_ok()
        {
            "podman"
        } else if run_command_extended(RunCommandArgs {
            command: "docker --version",
            output: Output::Silence,
            ..Default::default()
        })
        .is_ok()
        {
            "docker"
        } else {
            bail!("Host needs either podman or Docker installed!");
        };

        println!("Checking for build image updates");
        Command::new(program)
            .arg("pull")
            .arg(BUILDER_IMAGE)
            .output()
            .context("Failed to pull new builder image")?;

        Ok(Self {
            cmd: Command::new(program),
        })
    }

    pub fn run(&mut self) -> &mut Self {
        self.cmd.arg("run");
        self
    }

    pub fn rm(&mut self) -> &mut Self {
        self.cmd.arg("--rm");
        self
    }

    pub fn env(&mut self, key: &str, val: &str) -> &mut Self {
        self.cmd.arg("-e").arg(format!("{key}={val}"));
        self
    }

    pub fn volume(&mut self, src: &str, dest: &str) -> &mut Self {
        self.cmd.arg("-v").arg(format!("{src}:{dest}"));
        self
    }

    pub fn workdir(&mut self, dir: &str) -> &mut Self {
        self.cmd.arg("-w").arg(dir);
        self
    }

    pub fn arg(&mut self, arg: &str) -> &mut Self {
        self.cmd.arg(arg);
        self
    }

    pub fn setup_build_env(&mut self) -> Result<&mut Self> {
        let home = std::env::var("HOME").unwrap();
        let project_root = PROJECT_ROOT.clone();
        let project_root = project_root.display();

        self.run()
            .rm()
            .env("TERM", "xterm-256color")
            .volume(&project_root.to_string(), "/work-dir")
            .workdir("/work-dir")
            .volume(&format!("{home}/.cargo/registry"), "/root/.cargo/registry")
            .volume(&format!("{home}/.cargo/git"), "/root/.cargo/git");

        self.arg(BUILDER_IMAGE).arg("/bin/bash").arg("-c");
        Ok(self)
    }

    pub fn status(&mut self) -> Result<std::process::ExitStatus, std::io::Error> {
        self.cmd.status()
    }
}

/// create a base container command
pub fn build_base_container_command() -> Result<Container> {
    let mut container = Container::try_new()?;
    container.setup_build_env()?;
    Ok(container)
}

pub fn run_test_suite(
    test_dir: &str,
    prelude: &str,
    test_filters: Option<Vec<&str>>,
    test_output: &str,
    target_host: &str,
    default_test_profile: &str,
) -> Result<()> {
    let mut test_command = format!(
        "(cd {test_dir} && \
                sudo {prelude} \
                cargo-nextest nextest run \
                --workspace-remap=. --archive-file $HOME/caliptra-test-binaries.tar.zst \
                {test_output} --no-fail-fast "
    );
    if let Some(filters) = test_filters {
        test_command += "--profile=nightly ";
        for filter in filters {
            test_command += format!("-E \"{filter}\" ").as_str();
        }
    } else {
        test_command += format!("--profile={default_test_profile} ").as_str();
    }
    test_command += ")";
    // Run test suite.
    // Ignore error so we still copy the logs.
    let _ = run_command(target_host, test_command.as_str());
    println!("Copying test log from FPGA to junit.xml");
    rsync_file(target_host, "/tmp/junit.xml", ".", true)?;
    Ok(())
}

/// Download a bitstream from a Caliptra bitstream manifest
pub fn download_bitstream_pdi<P: AsRef<Path>>(target_host: &str, manifest: P) -> Result<()> {
    // Assumes bitstream file is placed in the current directory.
    let bitstream = bitstream_downloader::download_bitstream(manifest.as_ref())?;

    rsync_file(
        target_host,
        &bitstream.display().to_string(),
        "caliptra-bitstream.pdi",
        false,
    )
    .context("failed to copy tests to fpga")?;

    run_command(target_host, "sudo mkdir -p /lib/firmware")?;
    run_command(target_host, "sudo mv caliptra-bitstream.pdi /lib/firmware")?;
    run_command(
        target_host,
        r#"sudo bash -c 'echo "caliptra-bitstream.pdi" > /sys/class/fpga_manager/fpga0/firmware'"#,
    )?;
    Ok(())
}

pub fn build_caliptra_firmware(caliptra_workspace: &Path, fw_id: Option<&str>) -> Result<()> {
    let fw_dir = PathBuf::from("/tmp/caliptra-test-firmware");
    run_command_host("mkdir -p /tmp/caliptra-test-firmware/caliptra-test-firmware")?;
    let binaries = match fw_id {
        None => caliptra_builder::firmware::REGISTERED_FW.to_vec(),
        Some(fw_id) => caliptra_builder::firmware::REGISTERED_FW
            .iter()
            .cloned()
            .filter(|&fw| fw.bin_name == fw_id)
            .collect(),
    };

    for (fwid, elf_bytes) in
        caliptra_builder::build_firmware_elfs_uncached(Some(caliptra_workspace), &binaries).unwrap()
    {
        let elf_filename = fwid.elf_filename();
        std::fs::write(fw_dir.join(elf_filename), elf_bytes).unwrap();
    }
    Ok(())
}

pub fn build_mcu_rom(mcu_rev: &str) -> Result<()> {
    let mcu_dir = "/tmp/caliptra-mcu-sw";
    run_command_host(&format!(
        "[ -d {mcu_dir} ] || git clone https://github.com/chipsalliance/caliptra-mcu-sw {mcu_dir}"
    ))?;
    run_command_host(&format!(
        "cd {mcu_dir} && git fetch origin {mcu_rev} && git reset --hard {mcu_rev} && git submodule update --init --recursive"
    ))?;
    run_command_host(&format!(
        "cd {mcu_dir} && cargo xtask-fpga rom-build --platform fpga --features core_test"
    ))?;
    run_command_host(&format!(
        "cp {mcu_dir}/target/riscv32imc-unknown-none-elf/release/mcu-rom-fpga-core_test.bin /tmp/caliptra-test-firmware/mcu-rom-fpga.bin"
    ))?;
    Ok(())
}

pub fn check_ssh_access(target_host: &str) -> Result<()> {
    if run_command_extended(RunCommandArgs {
        target_host: Some(target_host),
        command: "true",
        output: Output::Silence,
    })
    .is_err()
    {
        bail!("Could not ssh to '{target_host}'. Please check your ssh connection and settings.");
    };

    Ok(())
}
