// Licensed under the Apache-2.0 license.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod crypto;
pub mod hand_off;
#[macro_use]
pub mod printer;
pub use hand_off::HandOffDataHandle;
pub use hand_off::FHT_INVALID_HANDLE;
pub use hand_off::FHT_MARKER;
pub use hand_off::{print_fht, report_handoff_error_and_halt, DataStore, FirmwareHandoffTable};

pub use printer::MutablePrinter;
