// Licensed under the Apache-2.0 license

use anyhow::{bail, Context, Result};
use clap::ValueEnum;

use super::{
    run_command, run_command_with_output,
    utils::{
        build_base_container_command, build_caliptra_firmware, build_mcu_rom, check_ssh_access,
        download_bitstream_pdi, rsync_file, run_test_suite, NextestArchiveCommand,
    },
    ActionHandler, BuildArgs, BuildTestArgs, TestArgs,
};

use crate::PROJECT_ROOT;

/// The FPGA configuration mode
#[derive(Copy, Clone, ValueEnum, Debug)]
pub enum Configuration {
    /// Testing `caliptra-sw` in `core` mode.
    Core,
    /// Running Core tests on a subsystem FPGA.
    CoreOnSubsystem,
}

impl Configuration {
    pub fn default_test_profile(&self) -> &str {
        match self {
            // Test profiles defined in caliptra-sw
            Self::Core => "fpga-core",
            Self::CoreOnSubsystem => "fpga-subsystem",
        }
    }
}

pub enum CommandExecutor {
    /// Runs commands for a FPGA.
    Core(Core),
    /// Runs commands for a core on subsystem FPGA.
    CoreOnSubsystem(CoreOnSubsystem),
}

impl From<Configuration> for CommandExecutor {
    fn from(value: Configuration) -> Self {
        match value {
            Configuration::Core => CommandExecutor::Core(Core::default()),
            Configuration::CoreOnSubsystem => {
                CommandExecutor::CoreOnSubsystem(CoreOnSubsystem::default())
            }
        }
    }
}

impl<'a> Configuration {
    pub fn cache(&'a self, cache_function: impl FnOnce(&'a str) -> Result<()>) -> Result<()> {
        match self {
            Self::Core => cache_function("core")?,
            Self::CoreOnSubsystem => cache_function("core-on-subsystem")?,
        }
        Ok(())
    }

    pub fn from_cache(cache_contents: &'a str) -> Result<Self> {
        match cache_contents {
            "core" => Ok(Configuration::Core),
            "core-on-subsystem" => Ok(Configuration::CoreOnSubsystem),
            _ => bail!("FPGA is not bootstrapped. Need to run `xtask fpga bootstrap`"),
        }
    }

    pub fn from_cmd(target_host: &str) -> Result<Self> {
        check_ssh_access(target_host)?;
        let cache_contents = run_command_with_output(target_host, "cat /dev/shm/fpga-config")?;
        let cache_contents = cache_contents.trim_end();
        Self::from_cache(cache_contents)
    }

    pub fn executor(self) -> CommandExecutor {
        self.into()
    }
}

impl<'a> ActionHandler<'a> for CommandExecutor {
    fn bootstrap(&self) -> Result<()> {
        match self {
            Self::Core(core) => core.bootstrap(),
            Self::CoreOnSubsystem(core) => core.bootstrap(),
        }
    }

    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        match self {
            Self::Core(core) => core.build(args),
            Self::CoreOnSubsystem(core) => core.build(args),
        }
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        // Delete the file if it exists. Sometimes the docker build fails silently. This will force
        // the rsync to fail in those cases.
        let _ = std::fs::remove_file("caliptra-test-binaries.tar.zst");
        match self {
            Self::Core(core) => core.build_test(args),
            Self::CoreOnSubsystem(core) => core.build_test(args),
        }
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        match self {
            Self::Core(core) => core.test(args)?,
            Self::CoreOnSubsystem(core) => core.test(args)?,
        }
        Ok(())
    }
}

impl CommandExecutor {
    pub fn set_target_host(&mut self, target_host: &str) -> &mut Self {
        match self {
            Self::Core(core) => core.set_target_host(target_host),
            Self::CoreOnSubsystem(core) => core.set_target_host(target_host),
        };
        self
    }
    pub fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) -> &mut Self {
        match self {
            Self::Core(core) => core.set_caliptra_fpga(caliptra_fpga),
            Self::CoreOnSubsystem(core) => core.set_caliptra_fpga(caliptra_fpga),
        };
        self
    }
}

#[derive(Clone, Default, Debug)]
/// Implements FPGA actions for a Core FPGA.
pub struct Core {
    target_host: String,
    caliptra_fpga: bool,
}

impl Core {
    fn set_target_host(&mut self, target_host: &str) {
        self.target_host = target_host.to_owned();
    }
    fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) {
        self.caliptra_fpga = caliptra_fpga;
    }
}

impl<'a> ActionHandler<'a> for Core {
    fn bootstrap(&self) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=main --depth=1";
        let target_host = &self.target_host;
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        let core_bitstream = PROJECT_ROOT
            .join("hw")
            .join("fpga")
            .join("bitstream_manifests")
            .join("core.toml");
        download_bitstream_pdi(target_host, &core_bitstream)?;
        Ok(())
    }
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        build_caliptra_firmware(&PROJECT_ROOT, args.fw_id.as_deref())?;
        rsync_file(
            &self.target_host,
            "/tmp/caliptra-test-firmware",
            "/tmp/caliptra-test-firmware",
            false,
        )?;
        Ok(())
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        let mut container = build_base_container_command()?;
        let cmd = NextestArchiveCommand::new("/work-dir")
            .features(&["fpga_realtime", "itrng"])
            .package_filter(args.package_filter.as_deref())
            .build();

        container.arg(&cmd);
        container
            .status()
            .context("failed to cross compile tests")?;
        rsync_file(
            &self.target_host,
            "caliptra-test-binaries.tar.zst",
            ".",
            false,
        )
        .context("failed to copy tests to fpga")?;
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let test_filters = args
            .test_filter
            .as_ref()
            .map(|filter_str| filter_str.split(',').collect());

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let prelude = "CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1 CPTRA_ROM_TYPE=ROM_WITH_UART";
        run_test_suite(
            "caliptra-sw",
            prelude,
            test_filters,
            to,
            &self.target_host,
            args.default_test_profile,
        )?;
        Ok(())
    }
}

#[derive(Clone, Default, Debug)]
/// Implements FPGA actions for a Core on Subsystem FPGA.
pub struct CoreOnSubsystem {
    target_host: String,
    caliptra_fpga: bool,
}

impl CoreOnSubsystem {
    fn set_target_host(&mut self, target_host: &str) {
        self.target_host = target_host.to_owned();
    }
    fn set_caliptra_fpga(&mut self, caliptra_fpga: bool) {
        self.caliptra_fpga = caliptra_fpga;
    }
}

impl<'a> ActionHandler<'a> for CoreOnSubsystem {
    fn bootstrap(&self) -> Result<()> {
        let bootstrap_cmd= "[ -d caliptra-sw ] || git clone https://github.com/chipsalliance/caliptra-sw --branch=main --depth=1";
        let target_host = &self.target_host;
        run_command(target_host, bootstrap_cmd).context("failed to clone caliptra-sw repo")?;

        // Only Petalinux images (similar to the Caliptra CI image) support segmented bitstreams.
        if !self.caliptra_fpga {
            return Ok(());
        }

        let subsystem_bitstream = PROJECT_ROOT
            .join("hw")
            .join("fpga")
            .join("bitstream_manifests")
            .join("subsystem.toml");
        download_bitstream_pdi(target_host, &subsystem_bitstream)?;
        Ok(())
    }
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()> {
        build_caliptra_firmware(&PROJECT_ROOT, args.fw_id.as_deref())?;
        build_mcu_rom(args.mcu_rev)?;
        rsync_file(
            &self.target_host,
            "/tmp/caliptra-test-firmware",
            "/tmp/caliptra-test-firmware",
            false,
        )?;
        Ok(())
    }

    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()> {
        let mut container = build_base_container_command()?;
        let cmd = NextestArchiveCommand::new("/work-dir")
            .features(&["fpga_subsystem", "itrng", "ocp-lock", "flash-boot"])
            .package_filter(args.package_filter.as_deref())
            .build();

        container.arg(&cmd);
        container
            .status()
            .context("failed to cross compile tests")?;
        rsync_file(
            &self.target_host,
            "caliptra-test-binaries.tar.zst",
            ".",
            false,
        )
        .context("failed to copy tests to fpga")?;
        Ok(())
    }

    fn test(&self, args: &'a TestArgs) -> Result<()> {
        let test_filters = args
            .test_filter
            .as_ref()
            .map(|filter_str| filter_str.split(',').collect());

        let to = if *args.test_output {
            "--no-capture"
        } else {
            "--test-threads=1"
        };

        let prelude = "CPTRA_UIO_NUM=0 CALIPTRA_PREBUILT_FW_DIR=/tmp/caliptra-test-firmware/caliptra-test-firmware CALIPTRA_IMAGE_NO_GIT_REVISION=1 CPTRA_MCU_ROM=/tmp/caliptra-test-firmware/caliptra-test-firmware/mcu-rom-fpga.bin CPTRA_ROM_TYPE=ROM_WITH_UART";
        run_test_suite(
            "caliptra-sw",
            prelude,
            test_filters,
            to,
            &self.target_host,
            args.default_test_profile,
        )?;
        Ok(())
    }
}
