/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod array;
mod error;
mod wait;

mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
mod hmac384;
mod key_vault;
mod kv_access;
mod mailbox;
mod pcr_bank;
mod sha256;
mod sha384;
mod sha384acc;
mod status_reporter;

pub type CaliptraResult<T> = Result<T, u32>;
pub use array::{Array4x12, Array4x4, Array4x8};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384Data, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Ecc384Signature,
};
pub use error::CptrComponent;
pub use error_reporter::{
    report_fw_error_fatal, report_fw_error_non_fatal, report_hw_error_fatal,
    report_hw_error_non_fatal,
};
pub use exit_ctrl::ExitCtrl;
pub use hmac384::Hmac384;
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use mailbox::{Mailbox, MailboxRecvTxn, MailboxSendTxn};
pub use pcr_bank::{PcrBank, PcrId};
pub use sha256::Sha256;
pub use sha384::{Sha384, Sha384Data, Sha384Digest};
pub use sha384acc::Sha384Acc;
pub use status_reporter::{report_boot_status, report_flow_status};

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;

        pub use uart::Uart;
    }
}
