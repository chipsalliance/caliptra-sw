// Licensed under the Apache-2.0 license.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod boot_status;
pub mod capabilities {
    pub use caliptra_api::Capabilities;
}
pub mod checksum {
    pub use caliptra_api::{calc_checksum, verify_checksum};
}
pub mod crypto;
pub mod dice;
pub mod error_handler;
pub mod fips;
pub mod keyids;
pub mod verifier;
pub mod wdt;

///merge imports
pub use hand_off::{
    DataStore, DataVaultRegister, FirmwareHandoffTable, HandOffDataHandle, Vault,
    FHT_INVALID_HANDLE, FHT_MARKER,
};

pub use boot_status::RomBootStatus;
pub use caliptra_api::mailbox as mailbox_api;
pub use caliptra_drivers::cprint;
pub use caliptra_drivers::cprintln;
pub use caliptra_drivers::fuse_log as fuse;
pub use caliptra_drivers::hand_off;
pub use caliptra_drivers::memory_layout;
pub use caliptra_drivers::pcr_log as pcr;
pub use caliptra_drivers::printer::HexBytes;
pub use caliptra_drivers::printer::Printer;
pub use error_handler::handle_fatal_error;
pub use fuse::{FuseLogEntry, FuseLogEntryId};
pub use pcr::{PcrLogEntry, PcrLogEntryId, RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR};

pub const FMC_ORG: u32 = 0x40000000;
pub const FMC_SIZE: u32 = 20 * 1024;
pub const RUNTIME_ORG: u32 = FMC_ORG + FMC_SIZE;
pub const RUNTIME_SIZE: u32 = 94 * 1024;

pub use memory_layout::{DATA_ORG, FHT_ORG, FHT_SIZE, MAN1_ORG};
pub use wdt::{restart_wdt, start_wdt, stop_wdt, WdtTimeout};
