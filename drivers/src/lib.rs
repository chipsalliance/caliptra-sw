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
pub mod hand_off;
mod hmac384;
mod hmac384_kdf;
mod key_vault;
mod kv_access;
mod lms;
mod mailbox;
pub mod memory_layout;
mod okref;
mod pcr_bank;
pub mod printer;
mod sha1;
mod sha256;
mod sha384;
mod sha384acc;
mod soc_ifc;
mod trng;
mod trng_ext;

pub use array::{Array4x12, Array4x4, Array4x5, Array4x8, Array4xN};
pub use array_concat::array_concat3;
pub use caliptra_error::{CaliptraError, CaliptraResult};
pub use csrng::{
    Csrng, HealthFailCounts as CsrngHealthFailCounts, Iter as CsrngIter, Seed as CsrngSeed,
};
pub use data_vault::{
    ColdResetEntry4, ColdResetEntry48, DataVault, WarmResetEntry4, WarmResetEntry48,
};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Seed, Ecc384Signature,
};
pub use error_reporter::{report_fw_error_fatal, report_fw_error_non_fatal};
pub use exit_ctrl::ExitCtrl;
pub use fuse_bank::{
    FuseBank, IdevidCertAttr, RomVerifyConfig, VendorPubKeyRevocation, X509KeyIdAlgo,
};
pub use hand_off::FirmwareHandoffTable;
pub use hmac384::{Hmac384, Hmac384Data, Hmac384Key, Hmac384Op, Hmac384Tag};
pub use hmac384_kdf::hmac384_kdf;
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use lms::{
    get_lmots_parameters, get_lms_parameters, HashValue, Lms, LmsResult, Sha192Digest,
    Sha256Digest, D_INTR, D_LEAF, D_MESG, D_PBLC,
};
pub use mailbox::{Mailbox, MailboxRecvTxn, MailboxSendTxn};
pub use okref::okmutref;
pub use okref::okref;
pub use pcr_bank::{PcrBank, PcrId};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha256::{Sha256, Sha256DigestOp};
pub use sha384::{Sha384, Sha384Digest, Sha384DigestOp};
pub use sha384acc::{Sha384Acc, Sha384AccOp};
pub use soc_ifc::{report_boot_status, Lifecycle, MfgFlags, ResetReason, SocIfc};
pub use trng::Trng;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;

        pub use uart::Uart;
    }
}
