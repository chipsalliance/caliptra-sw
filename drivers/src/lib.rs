/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod array;
pub mod error;
mod wait;

mod data_vault;
mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
mod fuse_bank;
mod hmac384;
mod key_vault;
mod kv_access;
mod mailbox;
mod pcr_bank;
mod reset;
mod sha1;
mod sha256;
mod sha384;
mod sha384acc;
pub mod state;
mod status_reporter;
mod lms;

pub type CaliptraResult<T> = Result<T, u32>;
pub use array::{Array4x12, Array4x4, Array4x5, Array4x8, Array4xN};
pub use data_vault::{
    ColdResetEntry4, ColdResetEntry48, DataVault, WarmResetEntry4, WarmResetEntry48,
};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384Data, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Ecc384Signature,
};
pub use error::CaliptraComponent;
pub use error_reporter::{
    report_fw_error_fatal, report_fw_error_non_fatal, report_hw_error_fatal,
    report_hw_error_non_fatal,
};
pub use exit_ctrl::ExitCtrl;
pub use fuse_bank::{FuseBank, IdevidCertAttr, VendorPubKeyRevocation, X509KeyIdAlgo};
pub use hmac384::{Hmac384, Hmac384Data, Hmac384Key, Hmac384Op, Hmac384Tag};
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use mailbox::{Mailbox, MailboxRecvTxn, MailboxSendTxn};
pub use pcr_bank::{PcrBank, PcrId};
pub use reset::{ResetReason, ResetService};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha256::{Sha256, Sha256DigestOp};
pub use sha384::{Sha384, Sha384Digest, Sha384DigestOp};
pub use sha384acc::{Sha384Acc, Sha384AccOp};
pub use state::{DeviceState, Lifecycle, MfgState};
pub use status_reporter::{report_boot_status, FlowStatus};
pub use lms::{
    candidate_ots_signature, hash_message, lookup_lmots_algorithm_type, get_lms_parameters,
    lookup_lms_algorithm_type, verify_lms_signature, HashValue, LmotsAlgorithmType,
    LmotsSignature, LmsAlgorithmType, LmsIdentifier, LmsSignature, Sha256Digest, Sha192Digest,
};
cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;

        pub use uart::Uart;
    }
}
