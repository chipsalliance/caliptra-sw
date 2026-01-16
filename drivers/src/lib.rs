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

mod aes;
mod bounded_address;
pub mod cmac_kdf;
mod csrng;
mod data_vault;
pub mod dma;
mod doe;
mod ecc384;
mod error_reporter;
mod exit_ctrl;
#[cfg(feature = "fips-test-hooks")]
pub mod fips_test_hooks;
mod fuse_bank;
pub mod fuse_log;
pub mod hand_off;
mod hkdf;
mod hmac;
mod hmac_kdf;
pub mod hpke;
mod key_vault;
mod kv_access;
mod lms;
mod mailbox;
pub mod memory_layout;
mod ml_kem;
mod mldsa87;
pub mod ocp_lock;
mod okref;
mod pcr_bank;
pub mod pcr_log;
pub mod pcr_reset;
mod persistent;
pub mod pic;
pub mod preconditioned_aes;
pub mod preconditioned_key;
pub mod printer;
mod sha1;
mod sha256;
pub mod sha2_512_384;
mod sha2_512_384acc;
mod sha3;
mod soc_ifc;
mod trng;
mod trng_ext;

pub use aes::{
    Aes, AesContext, AesGcmContext, AesGcmIv, AesKey, AesOperation, AES_BLOCK_SIZE_BYTES,
    AES_BLOCK_SIZE_WORDS, AES_CONTEXT_SIZE_BYTES, AES_GCM_CONTEXT_SIZE_BYTES,
};
pub use array::{
    Array4x12, Array4x16, Array4x4, Array4x5, Array4x8, Array4xN, LEArray4x1157, LEArray4x16,
    LEArray4x3, LEArray4x392, LEArray4x4, LEArray4x648, LEArray4x792, LEArray4x8,
};
pub use array_concat::array_concat3;
pub use bounded_address::{BoundedAddr, MemBounds, RomAddr};
pub use caliptra_error::{CaliptraError, CaliptraResult};
pub use cmac_kdf::cmac_kdf;
pub use csrng::{
    Csrng, HealthFailCounts as CsrngHealthFailCounts, Seed as CsrngSeed, MAX_SEED_WORDS,
};
pub use data_vault::{ColdResetEntries, DataVault, WarmResetEntries};
pub use dma::{
    AesDmaMode, AxiAddr, Dma, DmaMmio, DmaOtpCtrl, DmaReadTarget, DmaReadTransaction, DmaRecovery,
    DmaWriteOrigin, DmaWriteTransaction,
};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Seed, Ecc384Signature,
};
pub use error_reporter::{
    clear_fw_error_non_fatal, get_fw_error_non_fatal, report_fw_error_fatal,
    report_fw_error_non_fatal,
};
pub use exit_ctrl::ExitCtrl;
#[cfg(feature = "fips-test-hooks")]
pub use fips_test_hooks::FipsTestHook;
pub use fuse_bank::{FuseBank, IdevidCertAttr, VendorEccPubKeyRevocation, X509KeyIdAlgo};
pub use hand_off::FirmwareHandoffTable;
pub use hkdf::{hkdf_expand, hkdf_extract};
pub use hmac::{Hmac, HmacData, HmacKey, HmacMode, HmacOp, HmacTag};
pub use hmac_kdf::hmac_kdf;
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use lms::{
    get_lmots_parameters, get_lms_parameters, HashValue, Lms, LmsResult, Sha192Digest,
    Sha256Digest, D_INTR, D_LEAF, D_MESG, D_PBLC,
};
pub use mailbox::{
    Mailbox, MailboxRecvTxn, MailboxSendTxn, MBOX_SIZE_PASSIVE, MBOX_SIZE_SUBSYSTEM,
};
pub use ml_kem::{
    MlKem1024, MlKem1024Ciphertext, MlKem1024DecapsKey, MlKem1024EncapsKey, MlKem1024Message,
    MlKem1024MessageSource, MlKem1024Seed, MlKem1024Seeds, MlKem1024SharedKey,
    MlKem1024SharedKeyOut, MlKemResult,
};
pub use mldsa87::{
    Mldsa87, Mldsa87Msg, Mldsa87PrivKey, Mldsa87PubKey, Mldsa87Result, Mldsa87Seed, Mldsa87SignRnd,
    Mldsa87Signature,
};
pub use ocp_lock::HekSeedState;
pub use okref::okmutref;
pub use okref::okref;
pub use pcr_bank::{PcrBank, PcrId};
pub use pcr_reset::PcrResetCounter;
pub use persistent::fmc_alias_csr::FmcAliasCsrs;
#[cfg(any(feature = "fmc", feature = "runtime"))]
pub use persistent::FwPersistentData;
pub use persistent::IDEVID_CSR_ENVELOP_MARKER;
#[cfg(feature = "runtime")]
pub use persistent::{AuthManifestImageMetadataList, ExportedCdiEntry, ExportedCdiHandles};
pub use persistent::{
    BootMode, Ecc384IdevIdCsr, FuseLogArray, InitDevIdCsrEnvelope, Mldsa87IdevIdCsr, PcrLogArray,
    PersistentData, PersistentDataAccessor, RomPersistentData, StashMeasurementArray,
    ECC384_MAX_FMC_ALIAS_CSR_SIZE, ECC384_MAX_IDEVID_CSR_SIZE, FUSE_LOG_MAX_COUNT,
    MEASUREMENT_MAX_COUNT, MLDSA87_MAX_CSR_SIZE, PCR_LOG_MAX_COUNT,
};
pub use pic::{IntSource, Pic};
pub use sha1::{Sha1, Sha1Digest, Sha1DigestOp};
pub use sha256::{Sha256, Sha256Alg, Sha256DigestOp};
pub use sha2_512_384::{Sha2DigestOp, Sha2_512_384, Sha384Digest};
pub use sha2_512_384acc::{Sha2_512_384Acc, Sha2_512_384AccOp, ShaAccLockState, StreamEndianness};
pub use sha3::{Sha3, Sha3DigestOp};
pub use soc_ifc::{report_boot_status, CptraGeneration, Lifecycle, MfgFlags, ResetReason, SocIfc};
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
