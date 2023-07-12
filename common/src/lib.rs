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
pub mod memory_layout;
pub mod pcr;

///merge imports
pub use hand_off::{
    print_fht, report_handoff_error_and_halt, DataStore, DataVaultRegister, FirmwareHandoffTable,
    HandOffDataHandle, Vault, FHT_INVALID_HANDLE, FHT_MARKER,
};

pub use boot_status::RomBootStatus;
pub use fuse::{FuseLogEntry, FuseLogEntryId};
pub use pcr::{PcrLogEntry, PcrLogEntryId};
pub use printer::HexBytes;
pub use printer::MutablePrinter;
