// Licensed under the Apache-2.0 license
#![cfg_attr(not(test), no_std)]

mod capabilities;
mod checksum;
pub mod mailbox;
pub mod soc_mgr;

pub use caliptra_error as error;
pub use capabilities::Capabilities;
pub use checksum::{calc_checksum, verify_checksum};
pub use soc_mgr::SocManager;

#[derive(Debug, Eq, PartialEq)]
pub enum CaliptraApiError {
    ReadBuffTooSmall,
    BufferTooLargeForMailbox,
}
