// Licensed under the Apache-2.0 license.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod crypto;
pub mod dice;
pub mod hand_off;
#[macro_use]
pub mod printer;
///merge imports
pub use hand_off::{
    print_fht, report_handoff_error_and_halt, DataStore, DataVaultRegister, FirmwareHandoffTable,
    HandOffDataHandle, Vault, FHT_INVALID_HANDLE, FHT_MARKER,
};

pub use printer::MutablePrinter;
