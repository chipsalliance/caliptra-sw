// Licensed under the Apache-2.0 license

use caliptra_hw_model_types::DeviceLifecycle;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
pub struct Args {
    /// ROM binary path
    pub rom: PathBuf,

    /// Gdb Debugger
    #[arg(long)]
    pub gdb_port: Option<u16>,

    /// Current Firmware image file
    #[arg(long)]
    pub firmware: Option<PathBuf>,

    /// Update Firmware image file
    #[arg(long)]
    pub update_firmware: Option<PathBuf>,

    /// Trace instructions to a file in log-dir
    #[arg(long)]
    pub trace_instr: bool,

    /// 128-bit Unique Endpoint Id
    #[arg(long, default_value_t = u128::MAX)]
    pub ueid: u128,

    /// idevid certificate key id algorithm
    #[arg(long, value_enum, default_value_t = ArgsIdevidAlgo::Sha1)]
    pub idevid_key_id_algo: ArgsIdevidAlgo,

    /// Request IDevID CSR. Downloaded CSR is stored in log-dir
    #[arg(long)]
    pub req_idevid_csr: bool,

    /// Request LDevID Cert. Downloaded cert is stored in log-dir
    #[arg(long)]
    pub req_ldevid_cert: bool,

    /// Directory to log execution artifacts
    #[arg(long, default_value = "/tmp")]
    pub log_dir: PathBuf,

    /// Hash of the four Manufacturer Public Keys
    #[arg(long, default_value = "")]
    pub mfg_pk_hash: String,

    /// Owner Public Key Hash
    #[arg(long, default_value = "")]
    pub owner_pk_hash: String,

    /// Device Lifecycle State
    #[arg(long, value_enum, default_value_t = ArgsDeviceLifecycle::Unprovisioned)]
    pub device_lifecycle: ArgsDeviceLifecycle,

    /// Watchdog Timer Timeout in CPU Clock Cycles
    #[arg(long, default_value_t = EXPECTED_CALIPTRA_BOOT_TIME_IN_CYCLES)]
    pub wdt_timeout: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ArgsIdevidAlgo {
    Sha1,
    Sha256,
    Sha384,
    Fuse,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ArgsDeviceLifecycle {
    Unprovisioned,
    Manufacturing,
    Production,
}

impl From<ArgsDeviceLifecycle> for DeviceLifecycle {
    fn from(value: ArgsDeviceLifecycle) -> Self {
        match value {
            ArgsDeviceLifecycle::Manufacturing => DeviceLifecycle::Manufacturing,
            ArgsDeviceLifecycle::Production => DeviceLifecycle::Production,
            ArgsDeviceLifecycle::Unprovisioned => DeviceLifecycle::Unprovisioned,
        }
    }
}
