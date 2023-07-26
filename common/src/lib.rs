// Licensed under the Apache-2.0 license.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod crypto;
pub mod dice;
pub mod hand_off;
#[macro_use]
pub mod printer;
pub mod boot_status;
pub mod checksum;
pub mod fuse;
pub mod helpers;
pub mod keyids;
pub mod memory_layout;
pub mod pcr;

///merge imports
pub use hand_off::{
    print_fht, report_handoff_error_and_halt, DataStore, DataVaultRegister, FirmwareHandoffTable,
    HandOffDataHandle, Vault, FHT_INVALID_HANDLE, FHT_MARKER,
};

pub use boot_status::RomBootStatus;
pub use fuse::{FuseLogEntry, FuseLogEntryId};
pub use pcr::{PcrLogEntry, PcrLogEntryId, RT_FW_CURRENT_PCR, RT_FW_JOURNEY_PCR};
pub use printer::HexBytes;
pub use printer::MutablePrinter;

pub const FMC_ORG: u32 = 0x40000000;
pub const FMC_SIZE: u32 = 16 * 1024;
pub const RUNTIME_ORG: u32 = FMC_ORG + FMC_SIZE;
pub const RUNTIME_SIZE: u32 = 96 * 1024;

pub use memory_layout::{DATA_ORG, FHT_ORG, FHT_SIZE, MAN1_ORG};
