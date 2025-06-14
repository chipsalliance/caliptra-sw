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

mod bounded_address;
mod csrng;
mod data_vault;
mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
#[cfg(feature = "fips-test-hooks")]
pub mod fips_test_hooks;
mod fuse_bank;
pub mod fuse_log;
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
pub mod pcr_log;
pub mod pcr_reset;
mod persistent;
pub mod pic;
pub mod printer;
mod sha1;
mod sha256;
mod sha2_512_384acc;
mod sha384;
mod soc_ifc;
mod trng;
mod trng_ext;

pub use array::{Array4x12, Array4x16, Array4x4, Array4x5, Array4x8, Array4xN};
pub use array_concat::array_concat3;
pub use bounded_address::{BoundedAddr, MemBounds, RomAddr};
pub use caliptra_error::{CaliptraError, CaliptraResult};
pub use csrng::{Csrng, HealthFailCounts as CsrngHealthFailCounts, Seed as CsrngSeed};
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
#[cfg(feature = "fips-test-hooks")]
pub use fips_test_hooks::FipsTestHook;
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
pub use pcr_reset::PcrResetCounter;
pub use persistent::fmc_alias_csr::FmcAliasCsr;
#[cfg(feature = "runtime")]
pub use persistent::{AuthManifestImageMetadataList, ExportedCdiEntry, ExportedCdiHandles};

pub use persistent::{
    FuseLogArray, IdevIdCsr, PcrLogArray, PersistentData, PersistentDataAccessor,
    StashMeasurementArray, FUSE_LOG_MAX_COUNT, MAX_CSR_SIZE, MEASUREMENT_MAX_COUNT,
    PCR_LOG_MAX_COUNT,
};
pub use pic::{IntSource, Pic};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha256::{Sha256, Sha256Alg, Sha256DigestOp};
pub use sha2_512_384acc::{Sha2_512_384Acc, Sha2_512_384AccOp, ShaAccLockState};
pub use sha384::{Sha384, Sha384Digest, Sha384DigestOp};
pub use soc_ifc::{report_boot_status, Lifecycle, MfgFlags, ResetReason, SocIfc};
pub use trng::Trng;

#[allow(unused_imports)]
#[cfg(all(not(feature = "runtime"), not(feature = "no-cfi")))]
use caliptra_cfi_derive;
#[allow(unused_imports)]
#[cfg(all(feature = "runtime", not(feature = "no-cfi")))]
use caliptra_cfi_derive_git as caliptra_cfi_derive;
#[allow(unused_imports)]
#[cfg(all(not(feature = "runtime"), not(feature = "no-cfi")))]
use caliptra_cfi_lib;
#[allow(unused_imports)]
#[cfg(all(feature = "runtime", not(feature = "no-cfi")))]
use caliptra_cfi_lib_git as caliptra_cfi_lib;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;

        pub use uart::Uart;
    }
}
