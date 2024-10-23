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
    UnableToSetPauser,
    UnableToLockMailbox,
    UnableToReadMailbox,
    BufferTooLargeForMailbox,
    UnknownCommandStatus(u32),
    MailboxTimeout,
    MailboxCmdFailed(u32),
    UnexpectedMailboxFsmStatus {
        expected: u32,
        actual: u32,
    },
    MailboxRespInvalidFipsStatus(u32),
    MailboxRespInvalidChecksum {
        expected: u32,
        actual: u32,
    },
    MailboxRespTypeTooSmall,
    MailboxReqTypeTooSmall,
    MailboxNoResponseData,
    MailboxUnexpectedResponseLen {
        expected_min: u32,
        expected_max: u32,
        actual: u32,
    },
    UploadFirmwareUnexpectedResponse,
    UploadMeasurementResponseError,
    ReadBuffTooSmall,
    FusesAlreadyIniitalized,
    FuseDoneNotSet,
    StashMeasurementFailed,
}
