// Licensed under the Apache-2.0 license

use anyhow::Result;
use clap::Subcommand;
use configurations::Configuration;
use utils::{
    check_fpga_dependencies, check_host_dependencies, check_ssh_access, run_command,
    run_command_with_output,
};

mod configurations;

mod utils;

const DEFAULT_MCU_REV: &str = "02ea798304ccccff8e6b5a065781b3d5ed38b118";

pub struct BuildArgs<'a> {
    pub fw_id: &'a Option<String>,
    pub mcu_rev: &'a str,
}

pub struct BuildTestArgs<'a> {
    pub package_filter: &'a Option<String>,
}
pub struct TestArgs<'a> {
    pub test_filter: &'a Option<String>,
    pub test_output: &'a bool,
    pub default_test_profile: &'a str,
}
pub trait ActionHandler<'a> {
    fn bootstrap(&self) -> Result<()>;
    fn build(&self, args: &'a BuildArgs<'a>) -> Result<()>;
    fn build_test(&self, args: &'a BuildTestArgs<'a>) -> Result<()>;
    fn test(&self, args: &'a TestArgs) -> Result<()>;
}

#[derive(Subcommand)]
pub enum Fpga {
    /// Bootstraps an FPGA. This command should be run after each boot
    Bootstrap {
        #[arg(long, default_value = "caliptra-fpga")]
        target_host: String,
        #[arg(long, default_value_t = Configuration::Core, value_enum)]
        configuration: Configuration,
    },
    /// Build FPGA firmware
    Build {
        /// When set copy firmware to `target_host`
        #[arg(long, default_value = "caliptra-fpga")]
        target_host: String,

        /// Only build the specified Caliptra Firmware
        /// By default all Caliptra firmware binaries are built
        #[arg(long)]
        fw_id: Option<String>,

        /// The git revision of the MCU firmware to build
        #[arg(long, default_value = DEFAULT_MCU_REV)]
        mcu_rev: String,
    },
    /// Build FPGA test binaries
    BuildTest {
        /// When set copy test binaries to `target_host`
        #[arg(long, default_value = "caliptra-fpga")]
        target_host: String,
        /// Filter packages for the test archive. This can be used to reduce the total archive
        /// size and speed up `build-test` commands.
        ///
        /// Uses a `cargo-nextest` package filter-set, e.g. `package(caliptra-rom)`.
        #[arg(long)]
        package_filter: Option<String>,
    },
    /// Run FPGA tests
    Test {
        /// When set run commands over ssh to `target_host`
        #[arg(long, default_value = "caliptra-fpga")]
        target_host: String,
        /// A specific test filter to apply.
        #[arg(long)]
        test_filter: Option<String>,
        /// Print test output during execution.
        #[arg(long, default_value_t = false)]
        test_output: bool,
    },
}

fn is_module_loaded(module: &str, target_host: &str) -> Result<bool> {
    let stdout = run_command_with_output(target_host, "lsmod")?;
    Ok(stdout
        .lines()
        .any(|line| line.split_whitespace().next() == Some(module)))
}

pub fn fpga_entry(args: &Fpga) -> Result<()> {
    check_host_dependencies()?;
    match args {
        Fpga::Build {
            target_host,
            fw_id: calitpra_fw_id,
            mcu_rev,
        } => {
            println!("Building FPGA firmware");
            let config = Configuration::from_cmd(target_host)?;
            config
                .executor()
                .set_target_host(target_host)
                .build(&BuildArgs {
                    fw_id: calitpra_fw_id,
                    mcu_rev,
                })?;
        }
        Fpga::BuildTest {
            target_host,
            package_filter,
        } => {
            println!("Building FPGA tests");
            let config = Configuration::from_cmd(target_host)?;
            config
                .executor()
                .set_target_host(target_host)
                .build_test(&BuildTestArgs { package_filter })?;
        }
        Fpga::Bootstrap {
            target_host,
            configuration,
        } => {
            println!("Bootstrapping FPGA");
            println!("configuration: {:?}", configuration);

            check_ssh_access(target_host)?;
            check_fpga_dependencies(target_host)?;

            let hostname = run_command_with_output(target_host, "hostname")?;

            // skip this step for CI images. Kernel modules are already installed.
            let caliptra_fpga = hostname.trim_end() == "caliptra-fpga";

            let cache_function = |config_marker| {
                // Cache FPGA configuration in RAM. We need to re-bootstrap on power cycles.
                run_command(
                    target_host,
                    &format!("echo \"{config_marker}\" > /dev/shm/fpga-config"),
                )
            };

            configuration.cache(cache_function)?;
            configuration
                .executor()
                .set_target_host(target_host)
                .set_caliptra_fpga(caliptra_fpga)
                .bootstrap()?;
        }
        Fpga::Test {
            target_host,
            test_filter,
            test_output,
        } => {
            println!("Running test suite on FPGA");
            is_module_loaded("io_module", target_host)?;

            // Clear old test logs
            run_command(target_host, "(sudo rm /tmp/junit.xml || true)")?;

            let config = Configuration::from_cmd(target_host)?;
            config
                .executor()
                .set_target_host(target_host)
                .test(&TestArgs {
                    test_filter,
                    test_output,
                    default_test_profile: config.default_test_profile(),
                })?;
        }
    }

    Ok(())
}
