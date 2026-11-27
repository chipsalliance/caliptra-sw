// Licensed under the Apache-2.0 license
#![cfg_attr(not(test), no_std)]

mod capabilities;
pub mod checksum;
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

impl core::fmt::Display for CaliptraApiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CaliptraApiError::UnableToSetPauser => f.write_str("Unable to set PAUSER"),
            CaliptraApiError::UnableToLockMailbox => f.write_str("Unable to lock mailbox"),
            CaliptraApiError::UnableToReadMailbox => f.write_str("Unable to read mailbox"),
            CaliptraApiError::BufferTooLargeForMailbox => {
                f.write_str("Buffer too large for mailbox")
            }
            CaliptraApiError::UnknownCommandStatus(code) => {
                write!(f, "Unknown command status: 0x{code:08x}")
            }
            CaliptraApiError::MailboxTimeout => f.write_str("Mailbox timeout"),
            CaliptraApiError::MailboxCmdFailed(code) => {
                write!(f, "Mailbox cmd failed: 0x{code:08x}")
            }
            CaliptraApiError::UnexpectedMailboxFsmStatus { expected, actual } => {
                write!(
                    f,
                    "Unexpected FSM status: exp=0x{expected:08x} act=0x{actual:08x}"
                )
            }
            CaliptraApiError::MailboxRespInvalidFipsStatus(status) => {
                write!(f, "Invalid FIPS status: 0x{status:08x}")
            }
            CaliptraApiError::MailboxRespInvalidChecksum { expected, actual } => {
                write!(
                    f,
                    "Invalid checksum: exp=0x{expected:08x} act=0x{actual:08x}"
                )
            }
            CaliptraApiError::MailboxRespTypeTooSmall => f.write_str("Response type too small"),
            CaliptraApiError::MailboxReqTypeTooSmall => f.write_str("Request type too small"),
            CaliptraApiError::MailboxNoResponseData => f.write_str("No response data"),
            CaliptraApiError::MailboxUnexpectedResponseLen {
                expected_min,
                expected_max,
                actual,
            } => write!(
                f,
                "Unexpected resp len: min={expected_min} max={expected_max} actual={actual}"
            ),
            CaliptraApiError::UploadFirmwareUnexpectedResponse => {
                f.write_str("Unexpected response after firmware upload")
            }
            CaliptraApiError::UploadMeasurementResponseError => {
                f.write_str("Error in response after measurement upload")
            }
            CaliptraApiError::ReadBuffTooSmall => f.write_str("Read buffer too small"),
            CaliptraApiError::FusesAlreadyIniitalized => f.write_str("Fuses already initialized"),
            CaliptraApiError::FuseDoneNotSet => f.write_str("Fuse write done not set"),
            CaliptraApiError::StashMeasurementFailed => f.write_str("Stash measurement failed"),
        }
    }
}
