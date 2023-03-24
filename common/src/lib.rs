// Licensed under the Apache-2.0 license.

#![cfg_attr(not(feature = "std"), no_std)]
pub mod hand_off;
#[macro_use]
pub mod printer;
pub use hand_off::FirmwareHandoffTable;
pub use hand_off::FHT_MARKER;
pub use printer::MutablePrinter;
