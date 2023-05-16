/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod array;
mod array_concat;
mod wait;

mod csrng;
mod data_vault;
mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
mod fuse_bank;
mod hmac384;
mod key_vault;
mod kv_access;
mod lms;
mod mailbox;
mod okref;
mod pcr_bank;
mod reset;
mod sha1;
mod sha256;
mod sha384;
mod sha384acc;
pub mod state;
mod status_reporter;

pub use array::{Array4x12, Array4x4, Array4x5, Array4x8, Array4xN};
pub use array_concat::array_concat3;
pub use caliptra_error::{caliptra_err_def, CaliptraComponent, CaliptraError, CaliptraResult};
pub use csrng::{
    Csrng, HealthFailCounts as CsrngHealthFailCounts, Iter as CsrngIter, Seed as CsrngSeed,
};
pub use data_vault::{
    ColdResetEntry4, ColdResetEntry48, DataVault, WarmResetEntry4, WarmResetEntry48,
};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Ecc384Signature,
};
pub use error_reporter::{
    report_fw_error_fatal, report_fw_error_non_fatal, report_hw_error_fatal,
    report_hw_error_non_fatal,
};
pub use exit_ctrl::ExitCtrl;
pub use fuse_bank::{FuseBank, IdevidCertAttr, VendorPubKeyRevocation, X509KeyIdAlgo};
pub use hmac384::{Hmac384, Hmac384Data, Hmac384Key, Hmac384Op, Hmac384Tag};
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use lms::{
    lookup_lmots_algorithm_type, lookup_lms_algorithm_type, HashValue, LmotsAlgorithmType,
    LmotsSignature, Lms, LmsAlgorithmType, LmsIdentifier, LmsSignature, Sha192Digest, Sha256Digest,
};
pub use mailbox::{Mailbox, MailboxRecvTxn, MailboxSendTxn};
pub use okref::okref;
pub use pcr_bank::{PcrBank, PcrId};
pub use reset::{ResetReason, ResetService};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha256::{Sha256, Sha256DigestOp};
pub use sha384::{Sha384, Sha384Digest, Sha384DigestOp};
pub use sha384acc::{Sha384Acc, Sha384AccOp};
pub use state::{DeviceState, Lifecycle, MfgState};
pub use status_reporter::{report_boot_status, FlowStatus};
cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;

        pub use uart::Uart;
    }
}
