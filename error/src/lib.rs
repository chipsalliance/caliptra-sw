/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the library for error handling

--*/
#![cfg_attr(not(feature = "std"), no_std)]
use core::convert::From;
use core::num::NonZeroU32;

/// Caliptra Error Type
/// Derives debug, copy, clone, eq, and partial eq
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CaliptraError(pub NonZeroU32);
impl CaliptraError {
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("CaliptraError cannot be 0"),
        }
    }
    pub const DRIVER_SHA256_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x00020001);
    pub const DRIVER_SHA256_MAX_DATA: CaliptraError = CaliptraError::new_const(0x00020002);
    pub const DRIVER_SHA256_INVALID_SLICE: CaliptraError = CaliptraError::new_const(0x00020003);
    pub const DRIVER_SHA256_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x00020004);

    /// Driver Error: SHA384
    pub const DRIVER_SHA384_READ_DATA_KV_READ: CaliptraError = CaliptraError::new_const(0x00030001);
    pub const DRIVER_SHA384_READ_DATA_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00030002);
    pub const DRIVER_SHA384_READ_DATA_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00030003);
    pub const DRIVER_SHA384_INVALID_STATE_ERR: CaliptraError = CaliptraError::new_const(0x00030007);
    pub const DRIVER_SHA384_MAX_DATA_ERR: CaliptraError = CaliptraError::new_const(0x00030008);
    pub const DRIVER_SHA384_INVALID_KEY_SIZE: CaliptraError = CaliptraError::new_const(0x00030009);
    pub const DRIVER_SHA384_INVALID_SLICE: CaliptraError = CaliptraError::new_const(0x0003000A);
    pub const DRIVER_SHA384_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x0003000B);

    /// Driver Error: HMAC384
    pub const DRIVER_HMAC384_READ_KEY_KV_READ: CaliptraError = CaliptraError::new_const(0x00040001);
    pub const DRIVER_HMAC384_READ_KEY_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00040002);
    pub const DRIVER_HMAC384_READ_KEY_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00040003);
    pub const DRIVER_HMAC384_READ_DATA_KV_READ: CaliptraError =
        CaliptraError::new_const(0x00040004);
    pub const DRIVER_HMAC384_READ_DATA_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00040005);
    pub const DRIVER_HMAC384_READ_DATA_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00040006);
    pub const DRIVER_HMAC384_WRITE_TAG_KV_READ: CaliptraError =
        CaliptraError::new_const(0x00040007);
    pub const DRIVER_HMAC384_WRITE_TAG_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00040008);
    pub const DRIVER_HMAC384_WRITE_TAG_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00040009);
    pub const DRIVER_HMAC384_INVALID_KEY_SIZE: CaliptraError = CaliptraError::new_const(0x0004000a);
    pub const DRIVER_HMAC384_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x0004000b);
    pub const DRIVER_HMAC384_MAX_DATA: CaliptraError = CaliptraError::new_const(0x0004000c);
    pub const DRIVER_HMAC384_INVALID_SLICE: CaliptraError = CaliptraError::new_const(0x0004000d);
    pub const DRIVER_HMAC384_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x0004000e);

    /// Driver Error: ECC384    
    pub const DRIVER_ECC384_READ_SEED_KV_READ: CaliptraError = CaliptraError::new_const(0x00050001);
    pub const DRIVER_ECC384_READ_SEED_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00050002);
    pub const DRIVER_ECC384_READ_SEED_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00050003);

    pub const DRIVER_ECC384_WRITE_PRIV_KEY_KV_READ: CaliptraError =
        CaliptraError::new_const(0x00050004);
    pub const DRIVER_ECC384_WRITE_PRIV_KEY_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00050005);
    pub const DRIVER_ECC384_WRITE_PRIV_KEY_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00050006);

    pub const DRIVER_ECC384_READ_PRIV_KEY_KV_READ: CaliptraError =
        CaliptraError::new_const(0x00050007);
    pub const DRIVER_ECC384_READ_PRIV_KEY_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x00050008);
    pub const DRIVER_ECC384_READ_PRIV_KEY_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x00050009);

    pub const DRIVER_ECC384_READ_DATA_KV_READ: CaliptraError = CaliptraError::new_const(0x0005000a);
    pub const DRIVER_ECC384_READ_DATA_KV_WRITE: CaliptraError =
        CaliptraError::new_const(0x0005000b);
    pub const DRIVER_ECC384_READ_DATA_KV_UNKNOWN: CaliptraError =
        CaliptraError::new_const(0x0005000c);

    pub const DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00060001);
    pub const DRIVER_KV_ERASE_WRITE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00060002);

    pub const DRIVER_PCR_BANK_ERASE_WRITE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00070001);

    /// Mailbox Errors
    pub const DRIVER_MAILBOX_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x00080001);
    pub const DRIVER_MAILBOX_INVALID_DATA_LEN: CaliptraError = CaliptraError::new_const(0x00080002);
    pub const DRIVER_MAILBOX_NO_DATA_AVAIL: CaliptraError = CaliptraError::new_const(0x00080003);
    pub const DRIVER_MAILBOX_ENQUEUE_ERR: CaliptraError = CaliptraError::new_const(0x00080004);
    pub const DRIVER_MAILBOX_DEQUEUE_ERR: CaliptraError = CaliptraError::new_const(0x00080005);

    pub const DRIVER_SHA384ACC_INVALID_OP: CaliptraError = CaliptraError::new_const(0x00090001);
    pub const DRIVER_SHA384ACC_MAX_DATA_ERR: CaliptraError = CaliptraError::new_const(0x00090002);
    pub const DRIVER_SHA384ACC_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x00090003);

    pub const DRIVER_SHA1_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x000a0001);
    pub const DRIVER_SHA1_MAX_DATA: CaliptraError = CaliptraError::new_const(0x000a0002);
    pub const DRIVER_SHA1_INVALID_SLICE: CaliptraError = CaliptraError::new_const(0x000a0003);
    pub const DRIVER_SHA1_INDEX_OUT_OF_BOUNDS: CaliptraError = CaliptraError::new_const(0x000a0004);

    ///        ManifestMarkerMismatch = 1,
    pub const IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0001);
    ///        ManifestSizeMismatch = 2,
    pub const IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0002);
    ///        VendorPubKeyDigestInvalid = 3,
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0003);
    ///        VendorPubKeyDigestFailure = 4,
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0004);
    ///        VendorPubKeyDigestMismatch = 5,
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0005);
    ///        OwnerPubKeyDigestFailure = 6,
    pub const IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0006);
    ///        OwnerPubKeyDigestMismatch = 7,
    pub const IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0007);
    ///        VendorEccPubKeyIndexOutOfBounds = 8,
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x000b0008);
    ///        VendorEccPubKeyRevoked = 9,
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED: CaliptraError =
        CaliptraError::new_const(0x000b0009);
    ///        HeaderDigestFailure = 10,
    pub const IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000a);
    ///        VendorEccVerifyFailure = 11,
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000b);

    ///        VendorEccSignatureInvalid = 12,
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b000c);
    ///        VendorEccPubKeyIndexMismatch = 13,
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b000d);
    ///        OwnerEccVerifyFailure = 14,
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000e);
    ///        OwnerEccSignatureInvalid = 15,
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b000f);
    ///        TocEntryCountInvalid = 16,
    pub const IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0010);
    ///        TocDigestFailures = 17,
    pub const IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURES: CaliptraError =
        CaliptraError::new_const(0x000b0011);
    ///        TocDigestMismatch = 18,
    pub const IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0012);
    ///        FmcDigestFailure = 19,
    pub const IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0013);
    ///        FmcDigestMismatch = 20,
    pub const IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0014);
    ///        RuntimeDigestFailure = 21,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0015);
    ///        RuntimeDigestMismatch = 22,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0016);
    ///        FmcRuntimeOverlap = 23,
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP: CaliptraError =
        CaliptraError::new_const(0x000b0017);
    ///        FmcRuntimeIncorrectOrder = 24,
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER: CaliptraError =
        CaliptraError::new_const(0x000b0018);
    ///        OwnerPubKeyDigestInvalidArg = 25,
    pub const IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b0019);
    ///        OwnerEccSignatureInvalidArg = 26,
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b001a);
    ///        VendorPubKeyDigestInvalidArg = 27,
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b001b);
    ///        FmcRuntimeInvalidType = 28,
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_INVALID_TYPE: CaliptraError =
        CaliptraError::new_const(0x000b001c);

    ///        UpdateResetOwnerDigestFailure = 29,
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b001d);

    /// UpdateResetVenPubKeyIdxMismatch = 30,
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PUB_KEY_IDX_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b001e);

    ///    UpdateResetFmcDigestMismatch = 31,
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b001f);

    ///    UpdateResetVenPubKeyIdxOutOfBounds = 32,
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_VEN_PUB_KEY_IDX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x000b0020);

    ///  FmcLoadAddrInvalid = 33,
    pub const IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0021);
    ///    FmcLoadAddrUnaligned = 34,
    pub const IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0022);

    ///    FmcEntryPointInvalid = 35,
    pub const IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0023);
    ///  FmcEntryPointUnaligned = 36,
    pub const IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0024);

    ///  FmcSvnGreaterThanMaxSupported = 37,
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b0025);

    ///    FmcSvnLessThanMinSupported = 38,
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b0026);

    ///    FmcSvnLessThanFuse = 39,
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE: CaliptraError =
        CaliptraError::new_const(0x000b0027);

    /// RuntimeLoadAddrInvalid = 40,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0028);

    ///   RuntimeLoadAddrUnaligned = 41,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0029);
    /// RuntimeEntryPointInvalid = 42,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b002a);
    ///  RuntimeEntryPointUnaligned = 43,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b002b);
    /// RuntimeSvnGreaterThanMaxSupported = 44,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b002c);
    /// RuntimeSvnLessThanMinSupported = 45,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b002d);
    /// RuntimeSvnLessThanFuse = 46,
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE: CaliptraError =
        CaliptraError::new_const(0x000b002e);
    /// ImageLenMoreThanBundleSize = 47,
    pub const IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE: CaliptraError =
        CaliptraError::new_const(0x000b002f);

    /// Driver Error: LMS
    pub const DRIVER_LMS_INVALID_LMS_ALGO_TYPE: CaliptraError =
        CaliptraError::new_const(0x000c0001);
    pub const DRIVER_LMS_INVALID_LMOTS_ALGO_TYPE: CaliptraError =
        CaliptraError::new_const(0x000c0002);
    pub const DRIVER_LMS_INVALID_WINTERNITS_PARAM: CaliptraError =
        CaliptraError::new_const(0x000c0003);
    pub const DRIVER_LMS_INVALID_PVALUE: CaliptraError = CaliptraError::new_const(0x000c0004);

    pub const DRIVER_LMS_INVALID_HASH_WIDTH: CaliptraError = CaliptraError::new_const(0x000c0005);

    pub const DRIVER_LMS_INVALID_TREE_HEIGHT: CaliptraError = CaliptraError::new_const(0x000c0006);

    pub const DRIVER_LMS_INVALID_Q_VALUE: CaliptraError = CaliptraError::new_const(0x000c0007);

    pub const DRIVER_LMS_INVALID_INDEX: CaliptraError = CaliptraError::new_const(0x000c0008);

    pub const DRIVER_LMS_PATH_OUT_OF_BOUNDS: CaliptraError = CaliptraError::new_const(0x000c0009);

    /// Instantiate = 1,
    pub const DRIVER_CSRNG_INSTANTIATE: CaliptraError = CaliptraError::new_const(0x000d0001);

    /// Uninstantiate = 2,
    pub const DRIVER_CSRNG_UNINSTANTIATE: CaliptraError = CaliptraError::new_const(0x000d0002);
    /// Reseed = 3,
    pub const DRIVER_CSRNG_RESEED: CaliptraError = CaliptraError::new_const(0x000d0003);
    /// Generate = 4,
    pub const DRIVER_CSRNG_GENERATE: CaliptraError = CaliptraError::new_const(0x000d0004);
    /// Update = 5,
    pub const DRIVER_CSRNG_UPDATE: CaliptraError = CaliptraError::new_const(0x000d0005);

    pub const RUNTIME_INTERNAL: CaliptraError = CaliptraError::new_const(0x000E0001);
    pub const RUNTIME_UNIMPLEMENTED_COMMAND: CaliptraError = CaliptraError::new_const(0x000E0002);
    pub const RUNTIME_INSUFFICIENT_MEMORY: CaliptraError = CaliptraError::new_const(0x000E0003);
    pub const RUNTIME_ECDSA_VERIF_FAILED: CaliptraError = CaliptraError::new_const(0x000E0004);

    pub const FMC_RTL_ALIAS_UNIMPLEMENTED: CaliptraError = CaliptraError::new_const(0x000F0001);

    /// Initial Device ID Errors
    pub const ROM_IDEVID_CSR_BUILDER_INIT_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000001);
    pub const ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000002);
    pub const ROM_IDEVID_INVALID_CSR: CaliptraError = CaliptraError::new_const(0x01000003);
    pub const ROM_IDEVID_CSR_VERIFICATION_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000004);
    pub const ROM_IDEVID_CSR_OVERFLOW: CaliptraError = CaliptraError::new_const(0x01000005);

    /// Local Device ID Errors
    pub const ROM_LDEVID_CSR_VERIFICATION_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01010001);

    /// FMC Alias Layer : Certificate Verification Failure.
    pub const FMC_ALIAS_CERT_VERIFY: CaliptraError = CaliptraError::new_const(0x01020001);
    pub const FMC_ALIAS_MANIFEST_READ_FAILURE: CaliptraError = CaliptraError::new_const(0x01020002);
    pub const FMC_ALIAS_INVALID_IMAGE_SIZE: CaliptraError = CaliptraError::new_const(0x01020003);
    pub const FMC_ALIAS_MAILBOX_STATE_INCONSISTENT: CaliptraError =
        CaliptraError::new_const(0x01020004);

    /// Update Reset Errors
    pub const ROM_UPDATE_RESET_FLOW_MANIFEST_READ_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01030002);
    pub const ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND: CaliptraError =
        CaliptraError::new_const(0x01030003);
    pub const ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01030004);

    // ROM Errors
    /// Global Scope  : NMI  
    pub const ROM_GLOBAL_NMI: CaliptraError = CaliptraError::new_const(0x01040001);
    /// Global Scope : Exception  
    pub const ROM_GLOBAL_EXCEPTION: CaliptraError = CaliptraError::new_const(0x01040002);
    ///  Global Scope : Panic
    pub const ROM_GLOBAL_PANIC: CaliptraError = CaliptraError::new_const(0x01040003);

    pub const ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID: CaliptraError =
        CaliptraError::new_const(0x01040004);

    pub const ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH: CaliptraError =
        CaliptraError::new_const(0x01040005);

    pub const ROM_KAT_SHA256_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90010001);
    pub const ROM_KAT_SHA256_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90010002);

    pub const ROM_KAT_SHA384_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90020001);
    pub const ROM_KAT_SHA384_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90020002);

    /// HMAC-384 KAT
    /// HmacFailure
    pub const ROM_KAT_HMAC384_FAILURE: CaliptraError = CaliptraError::new_const(0x90030001);
    pub const ROM_KAT_HMAC384_TAG_MISMATCH: CaliptraError = CaliptraError::new_const(0x90030002);

    pub const ROM_KAT_ECC384_SIGNATURE_GENERATE_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90040001);
    pub const ROM_KAT_ECC384_SIGNATURE_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90040002);
    pub const ROM_KAT_ECC384_SIGNATURE_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x90040003);

    /// SHA384 Accelerator KAT
    pub const ROM_KAT_SHA384_ACC_DIGEST_START_OP_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90050001);
    pub const ROM_KAT_SHA384_ACC_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90050002);
    pub const ROM_KAT_SHA384_ACC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x90050003);

    /// SHA1 KAT
    pub const ROM_KAT_SHA1_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90050001);
    pub const ROM_KAT_SHA1_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90050002);

    /// LmsKat = 0x9007,
    pub const ROM_KAT_LMS_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90070001);
    pub const ROM_KAT_LMS_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90070002);
}

impl From<core::num::NonZeroU32> for crate::CaliptraError {
    fn from(val: core::num::NonZeroU32) -> Self {
        crate::CaliptraError(val)
    }
}
impl From<CaliptraError> for core::num::NonZeroU32 {
    fn from(val: CaliptraError) -> Self {
        val.0
    }
}
impl From<CaliptraError> for u32 {
    fn from(val: CaliptraError) -> Self {
        core::num::NonZeroU32::from(val).get()
    }
}

pub type CaliptraResult<T> = Result<T, CaliptraError>;
