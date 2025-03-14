/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![cfg_attr(not(feature = "std"), no_std)]

mod array;
mod array_concat;
mod wait;

mod bounded_address;
mod csrng;
mod data_vault;
mod dma;
mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
#[cfg(feature = "fips-test-hooks")]
pub mod fips_test_hooks;
mod fuse_bank;
pub mod fuse_log;
pub mod hand_off;
mod hmac;
mod hmac_kdf;
mod key_vault;
mod kv_access;
mod lms;
mod mailbox;
pub mod memory_layout;
mod mldsa87;
mod okref;
mod pcr_bank;
pub mod pcr_log;
pub mod pcr_reset;
mod persistent;
pub mod pic;
pub mod printer;
mod sha1;
mod sha256;
pub mod sha2_512_384;
mod sha2_512_384acc;
mod soc_ifc;
mod trng;
mod trng_ext;

pub use array::{Array4x4, Array4x5, Array4x8, Array4x12, Array4x16, Array4xN};
pub use array_concat::array_concat3;
pub use bounded_address::{BoundedAddr, MemBounds, RomAddr};
pub use caliptra_error::{CaliptraError, CaliptraResult};
pub use csrng::{Csrng, HealthFailCounts as CsrngHealthFailCounts, Seed as CsrngSeed};
pub use data_vault::{ColdResetEntries, DataVault, WarmResetEntries};
pub use dma::{
    AxiAddr, Dma, DmaReadTarget, DmaReadTransaction, DmaRecovery, DmaWriteOrigin,
    DmaWriteTransaction,
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
pub use fuse_bank::{FuseBank, IdevidCertAttr, VendorEccPubKeyRevocation, X509KeyIdAlgo};
pub use hand_off::FirmwareHandoffTable;
pub use hmac::{Hmac, HmacData, HmacKey, HmacMode, HmacOp, HmacTag};
pub use hmac_kdf::hmac_kdf;
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use lms::{
    D_INTR, D_LEAF, D_MESG, D_PBLC, HashValue, Lms, LmsResult, Sha192Digest, Sha256Digest,
    get_lmots_parameters, get_lms_parameters,
};
pub use mailbox::{Mailbox, MailboxRecvTxn, MailboxSendTxn};
pub use mldsa87::{
    Mldsa87, Mldsa87Msg, Mldsa87PrivKey, Mldsa87PubKey, Mldsa87Result, Mldsa87Seed, Mldsa87SignRnd,
    Mldsa87Signature,
};
pub use okref::okmutref;
pub use okref::okref;
pub use pcr_bank::{PcrBank, PcrId};
pub use pcr_reset::PcrResetCounter;
#[cfg(feature = "runtime")]
pub use persistent::AuthManifestImageMetadataList;
pub use persistent::fmc_alias_csr::FmcAliasCsr;
pub use persistent::{
    ECC384_MAX_CSR_SIZE, Ecc384IdevIdCsr, FUSE_LOG_MAX_COUNT, FuseLogArray, InitDevIdCsrEnvelope,
    MEASUREMENT_MAX_COUNT, MLDSA87_MAX_CSR_SIZE, Mldsa87IdevIdCsr, PCR_LOG_MAX_COUNT, PcrLogArray,
    PersistentData, PersistentDataAccessor, StashMeasurementArray,
};
pub use pic::{IntSource, Pic};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha2_512_384::{Sha2_512_384, Sha2DigestOp, Sha384Digest};
pub use sha2_512_384acc::{Sha2_512_384Acc, Sha2_512_384AccOp, ShaAccLockState};
pub use sha256::{Sha256, Sha256Alg, Sha256DigestOp};
pub use soc_ifc::{Lifecycle, MfgFlags, ResetReason, SocIfc, report_boot_status};
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
