// Licensed under the Apache-2.0 license

use caliptra_api_types::{DeviceLifecycle, Fuses, DEFAULT_FIELD_ENTROPY, DEFAULT_UDS_SEED};
use serde_derive::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Test environment settings
    pub env: Environment,
    /// Expected state of Caliptra after attempting to boot
    pub end_state: StatusRegisters,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Environment {
    // Which UDS seed to use
    pub uds: UdsOptions,
    // Which field entropy to use
    pub field_entropy: FieldEntropyOptions,
    pub fuses: Fuses,
    /// Registers that are supposed to be set at the same time as fuses
    pub registers: BootRegisters,
    /// Enable debug for the platform
    pub enable_debug: bool,
    /// device_lifecycle value in in cptra_security_state
    pub lifecycle: DeviceLifecycle,
    /// Value of the Caliptra obfuscation key
    pub obf_key: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct BootRegisters {
    pub dbg_manuf_service_reg: u32,
    pub repcnt_thresh: Option<u32>,
    pub adaptp_thresh: Option<u32>,
    pub valid_pauser: Vec<u32>,
    pub wdt_timeout_cycles: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum UdsOptions {
    #[default]
    A,
    B,
}

impl UdsOptions {
    pub fn uds(&self) -> [u32; 12] {
        match self {
            UdsOptions::A => DEFAULT_UDS_SEED,
            UdsOptions::B => [
                0x10010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
                0x1c1d1e1f, 0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum FieldEntropyOptions {
    #[default]
    Empty,
    A,
    B,
}

impl FieldEntropyOptions {
    pub fn field_entropy(&self) -> [u32; 8] {
        match self {
            FieldEntropyOptions::Empty => [0u32; 8],
            FieldEntropyOptions::A => DEFAULT_FIELD_ENTROPY,
            FieldEntropyOptions::B => [
                0x81818283, 0x84858687, 0x88898a8b, 0x8c8d8e8f, 0x90919293, 0x94959697, 0x98999a9b,
                0x9c9d9e9f,
            ],
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct StatusRegisters {
    pub cptra_hw_fatal: u32,
    pub cptra_hw_non_fatal: u32,
    pub cptra_fw_fatal: u32,
    pub cptra_fw_non_fatal: u32,
    pub cptra_security_state: u32,
    pub cptra_dbg_manuf_service_reg: u32,
    pub cptra_flow_status: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Deserialize)]
pub enum ExpectedStage {
    ReadyForFuses,
    ReadyForFw,
    #[default]
    ReadyForRuntime,
}

#[derive(Debug, Deserialize)]
pub struct DevIdKeys {
    pub idev_uds_a_debug_disabled: String,
    pub idev_uds_a_debug_enabled: String,
    pub idev_uds_b: String,
    pub ldev_uds_a_fe_0_debug_disabled: String,
    pub ldev_uds_a_fe_0_debug_enabled: String,
    pub ldev_uds_a_fe_a: String,
    pub ldev_uds_a_fe_b: String,
    pub ldev_uds_b_fe_a: String,
}
