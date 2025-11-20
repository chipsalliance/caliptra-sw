/*++

Licensed under the Apache-2.0 license.

File Name:

    error.rs

Abstract:

    File contains API and macros used by the library for error handling

--*/
#![cfg_attr(not(feature = "std"), no_std)]
use core::convert::From;
use core::num::{NonZeroU32, TryFromIntError};

/// Caliptra Error Type
/// Derives debug, copy, clone, eq, and partial eq
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CaliptraError(pub NonZeroU32);

/// Macro to define error constants ensuring uniqueness
///
/// This macro takes a list of (name, value, doc) tuples and generates
/// constant definitions for each error code.
#[macro_export]
macro_rules! define_error_constants {
    ($(($name:ident, $value:expr, $doc:expr)),* $(,)?) => {
        $(
            #[doc = $doc]
            pub const $name: CaliptraError = CaliptraError::new_const($value);
        )*

        #[cfg(test)]
        /// Returns a vector of all defined error constants for testing uniqueness
        pub fn all_constants() -> Vec<(& 'static str, u32)> {
            vec![
                $(
                    (stringify!($name), $value),
                )*
            ]
        }
    };
}

impl CaliptraError {
    /// Create a caliptra error; intended to only be used from const contexts, as we don't want
    /// runtime panics if val is zero. The preferred way to get a CaliptraError from a u32 is to
    /// use `CaliptraError::try_from()` from the `TryFrom` trait impl.
    const fn new_const(val: u32) -> Self {
        match NonZeroU32::new(val) {
            Some(val) => Self(val),
            None => panic!("CaliptraError cannot be 0"),
        }
    }

    define_error_constants![
        (
            DRIVER_BAD_DATASTORE_VAULT_TYPE,
            0x00010001,
            "Driver Error: Bad Datastore Vault Type"
        ),
        (
            DRIVER_BAD_DATASTORE_REG_TYPE,
            0x00010002,
            "Driver Error: Bad Datastore Register Type"
        ),
        (
            DRIVER_SHA256_INVALID_STATE,
            0x00020001,
            "Driver Error: SHA256 Invalid State"
        ),
        (
            DRIVER_SHA256_MAX_DATA,
            0x00020002,
            "Driver Error: SHA256 Max Data"
        ),
        (
            DRIVER_SHA256_INVALID_SLICE,
            0x00020003,
            "Driver Error: SHA256 Invalid Slice"
        ),
        (
            DRIVER_SHA256_INDEX_OUT_OF_BOUNDS,
            0x00020004,
            "Driver Error: SHA256 Index Out of Bounds"
        ),
        (
            DRIVER_SHA384_READ_DATA_KV_READ,
            0x00030001,
            "Driver Error: SHA384 Read Data KV Read"
        ),
        (
            DRIVER_SHA384_READ_DATA_KV_WRITE,
            0x00030002,
            "Driver Error: SHA384 Read Data KV Write"
        ),
        (
            DRIVER_SHA384_READ_DATA_KV_UNKNOWN,
            0x00030003,
            "Driver Error: SHA384 Read Data KV Unknown"
        ),
        (
            DRIVER_SHA384_INVALID_STATE_ERR,
            0x00030007,
            "Driver Error: SHA384 Invalid State"
        ),
        (
            DRIVER_SHA384_MAX_DATA_ERR,
            0x00030008,
            "Driver Error: SHA384 Max Data"
        ),
        (
            DRIVER_SHA384_INVALID_KEY_SIZE,
            0x00030009,
            "Driver Error: SHA384 Invalid Key Size"
        ),
        (
            DRIVER_SHA384_INVALID_SLICE,
            0x0003000A,
            "Driver Error: SHA384 Invalid Slice"
        ),
        (
            DRIVER_SHA384_INDEX_OUT_OF_BOUNDS,
            0x0003000B,
            "Driver Error: SHA384 Index Out of Bounds"
        ),
        (
            DRIVER_SHA2_512_384ACC_UNEXPECTED_ACQUIRED_LOCK_STATE,
            0x00038000,
            "Driver Error: SHA2_512_384ACC Unexpected Acquired Lock State"
        ),
        (
            DRIVER_HMAC384_READ_KEY_KV_READ,
            0x00040001,
            "Driver Error: HMAC384 Read Key KV Read"
        ),
        (
            DRIVER_HMAC384_READ_KEY_KV_WRITE,
            0x00040002,
            "Driver Error: HMAC384 Read Key KV Write"
        ),
        (
            DRIVER_HMAC384_READ_KEY_KV_UNKNOWN,
            0x00040003,
            "Driver Error: HMAC384 Read Key KV Unknown"
        ),
        (
            DRIVER_HMAC384_READ_DATA_KV_READ,
            0x00040004,
            "Driver Error: HMAC384 Read Data KV Read"
        ),
        (
            DRIVER_HMAC384_READ_DATA_KV_WRITE,
            0x00040005,
            "Driver Error: HMAC384 Read Data KV Write"
        ),
        (
            DRIVER_HMAC384_READ_DATA_KV_UNKNOWN,
            0x00040006,
            "Driver Error: HMAC384 Read Data KV Unknown"
        ),
        (
            DRIVER_HMAC384_WRITE_TAG_KV_READ,
            0x00040007,
            "Driver Error: HMAC384 Write Tag KV Read"
        ),
        (
            DRIVER_HMAC384_WRITE_TAG_KV_WRITE,
            0x00040008,
            "Driver Error: HMAC384 Write Tag KV Write"
        ),
        (
            DRIVER_HMAC384_WRITE_TAG_KV_UNKNOWN,
            0x00040009,
            "Driver Error: HMAC384 Write Tag KV Unknown"
        ),
        (
            DRIVER_HMAC384_INVALID_STATE,
            0x0004000b,
            "Driver Error: HMAC384 Invalid State"
        ),
        (
            DRIVER_HMAC384_MAX_DATA,
            0x0004000c,
            "Driver Error: HMAC384 Max Data"
        ),
        (
            DRIVER_HMAC384_INVALID_SLICE,
            0x0004000d,
            "Driver Error: HMAC384 Invalid Slice"
        ),
        (
            DRIVER_HMAC384_INDEX_OUT_OF_BOUNDS,
            0x0004000e,
            "Driver Error: HMAC384 Index Out of Bounds"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_READ,
            0x00050001,
            "Driver Error: ECC384 Read Seed KV Read"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_WRITE,
            0x00050002,
            "Driver Error: ECC384 Read Seed KV Write"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
            0x00050003,
            "Driver Error: ECC384 Read Seed KV Unknown"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_READ,
            0x00050004,
            "Driver Error: ECC384 Write Private Key KV Read"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_WRITE,
            0x00050005,
            "Driver Error: ECC384 Write Private Key KV Write"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_UNKNOWN,
            0x00050006,
            "Driver Error: ECC384 Write Private Key KV Unknown"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_READ,
            0x00050007,
            "Driver Error: ECC384 Read Private Key KV Read"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_WRITE,
            0x00050008,
            "Driver Error: ECC384 Read Private Key KV Write"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_UNKNOWN,
            0x00050009,
            "Driver Error: ECC384 Read Private Key KV Unknown"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_READ,
            0x0005000a,
            "Driver Error: ECC384 Read Data KV Read"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_WRITE,
            0x0005000b,
            "Driver Error: ECC384 Read Data KV Write"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_UNKNOWN,
            0x0005000c,
            "Driver Error: ECC384 Read Data KV Unknown"
        ),
        (
            DRIVER_ECC384_KEYGEN_PAIRWISE_CONSISTENCY_FAILURE,
            0x0005000d,
            "Driver Error: ECC384 Keygen Pairwise Consistency Failure"
        ),
        (
            DRIVER_ECC384_SIGN_VALIDATION_FAILED,
            0x0005000e,
            "Driver Error: ECC384 Sign Validation Failed"
        ),
        (
            DRIVER_ECC384_SCALAR_RANGE_CHECK_FAILED,
            0x0005000f,
            "Driver Error: ECC384 Scalar Range Check Failed"
        ),
        (
            DRIVER_ECC384_KEYGEN_BAD_USAGE,
            0x00050010,
            "Driver Error: ECC384 Keygen Bad Usage"
        ),
        (
            DRIVER_ECC384_HW_ERROR,
            0x00050011,
            "Driver Error: ECC384 Hardware Error"
        ),
        (
            DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE,
            0x00060001,
            "Driver Error: KV Erase Use Lock Set Failure"
        ),
        (
            DRIVER_KV_ERASE_WRITE_LOCK_SET_FAILURE,
            0x00060002,
            "Driver Error: KV Erase Write Lock Set Failure"
        ),
        (
            DRIVER_PCR_BANK_ERASE_WRITE_LOCK_SET_FAILURE,
            0x00070001,
            "Driver Error: PCR Bank Erase Write Lock Set Failure"
        ),
        (
            DRIVER_MAILBOX_INVALID_STATE,
            0x00080001,
            "Driver Error: Mailbox Invalid State"
        ),
        (
            DRIVER_MAILBOX_INVALID_DATA_LEN,
            0x00080002,
            "Driver Error: Mailbox Invalid Data Length"
        ),
        (
            DRIVER_MAILBOX_ENQUEUE_ERR,
            0x00080004,
            "Driver Error: Mailbox Enqueue Error"
        ),
        (
            DRIVER_MAILBOX_UNCORRECTABLE_ECC,
            0x00080005,
            "Driver Error: Mailbox Uncorrectable ECC"
        ),
        (
            DRIVER_SHA2_512_384ACC_INDEX_OUT_OF_BOUNDS,
            0x00090003,
            "Driver Error: SHA2_512_384ACC Index Out of Bounds"
        ),
        (
            DRIVER_SHA1_INVALID_STATE,
            0x000a0001,
            "Driver Error: SHA1 Invalid State"
        ),
        (
            DRIVER_SHA1_MAX_DATA,
            0x000a0002,
            "Driver Error: SHA1 Max Data"
        ),
        (
            DRIVER_SHA1_INVALID_SLICE,
            0x000a0003,
            "Driver Error: SHA1 Invalid Slice"
        ),
        (
            DRIVER_SHA1_INDEX_OUT_OF_BOUNDS,
            0x000a0004,
            "Driver Error: SHA1 Index Out of Bounds"
        ),
        // Image Verifier Errors
        (
            IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH,
            0x000b0001,
            "Image Verifier Error: Manifest Marker Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH,
            0x000b0002,
            "Image Verifier Error: Manifest Size Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID,
            0x000b0003,
            "Image Verifier Error: Vendor Public Key Digest Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE,
            0x000b0004,
            "Image Verifier Error: Vendor Public Key Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH,
            0x000b0005,
            "Image Verifier Error: Vendor Public Key Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE,
            0x000b0006,
            "Image Verifier Error: Owner Public Key Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH,
            0x000b0007,
            "Image Verifier Error: Owner Public Key Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS,
            0x000b0008,
            "Image Verifier Error: Vendor ECC Public Key Index Out of Bounds"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED,
            0x000b0009,
            "Image Verifier Error: Vendor ECC Public Key Revoked"
        ),
        (
            IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE,
            0x000b000a,
            "Image Verifier Error: Header Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE,
            0x000b000b,
            "Image Verifier Error: Vendor ECC Verify Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID,
            0x000b000c,
            "Image Verifier Error: Vendor ECC Signature Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH,
            0x000b000d,
            "Image Verifier Error: Vendor ECC Public Key Index Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE,
            0x000b000e,
            "Image Verifier Error: Owner ECC Verify Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID,
            0x000b000f,
            "Image Verifier Error: Owner ECC Signature Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID,
            0x000b0010,
            "Image Verifier Error: TOC Entry Count Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURE,
            0x000b0011,
            "Image Verifier Error: TOC Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH,
            0x000b0012,
            "Image Verifier Error: TOC Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE,
            0x000b0013,
            "Image Verifier Error: FMC Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH,
            0x000b0014,
            "Image Verifier Error: FMC Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE,
            0x000b0015,
            "Image Verifier Error: Runtime Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
            0x000b0016,
            "Image Verifier Error: Runtime Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP,
            0x000b0017,
            "Image Verifier Error: FMC Runtime Overlap"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER,
            0x000b0018,
            "Image Verifier Error: FMC Runtime Incorrect Order"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG,
            0x000b0019,
            "Image Verifier Error: Owner ECC Public Key Invalid Argument"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG,
            0x000b001a,
            "Image Verifier Error: Owner ECC Signature Invalid Argument"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG,
            0x000b001b,
            "Image Verifier Error: Vendor Public Key Digest Invalid Argument"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG,
            0x000b001c,
            "Image Verifier Error: Vendor ECC Signature Invalid Argument"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE,
            0x000b001d,
            "Image Verifier Error: Update Reset Owner Digest Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH,
            0x000b001e,
            "Image Verifier Error: Update Reset Vendor ECC Public Key Index Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH,
            0x000b001f,
            "Image Verifier Error: Update Reset FMC Digest Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID,
            0x000b0021,
            "Image Verifier Error: FMC Load Address Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED,
            0x000b0022,
            "Image Verifier Error: FMC Load Address Unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID,
            0x000b0023,
            "Image Verifier Error: FMC Entry Point Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED,
            0x000b0024,
            "Image Verifier Error: FMC Entry Point Unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED,
            0x000b0025,
            "Image Verifier Error: FMC SVN Greater Than Max Supported"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED,
            0x000b0026,
            "Image Verifier Error: FMC SVN Less Than Min Supported"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE,
            0x000b0027,
            "Image Verifier Error: FMC SVN Less Than Fuse"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID,
            0x000b0028,
            "Image Verifier Error: Runtime Load Address Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED,
            0x000b0029,
            "Image Verifier Error: Runtime Load Address Unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID,
            0x000b002a,
            "Image Verifier Error: Runtime Entry Point Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED,
            0x000b002b,
            "Image Verifier Error: Runtime Entry Point Unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED,
            0x000b002c,
            "Image Verifier Error: Runtime SVN Greater Than Max Supported"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED,
            0x000b002d,
            "Image Verifier Error: Runtime SVN Less Than Min Supported"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE,
            0x000b002e,
            "Image Verifier Error: Runtime SVN Less Than Fuse"
        ),
        (
            IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE,
            0x000b002f,
            "Image Verifier Error: Image Length More Than Bundle Size"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH,
            0x000b0030,
            "Image Verifier Error: Vendor LMS Public Key Index Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE,
            0x000b0031,
            "Image Verifier Error: Vendor LMS Verify Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_OUT_OF_BOUNDS,
            0x000b0032,
            "Image Verifier Error: Vendor LMS Public Key Index Out of Bounds"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID,
            0x000b0033,
            "Image Verifier Error: Vendor LMS Signature Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP,
            0x000b0034,
            "Image Verifier Error: FMC Runtime Load Address Overlap"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_LMS_VERIFY_FAILURE,
            0x000b0036,
            "Image Verifier Error: Owner LMS Verify Failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID,
            0x000b0038,
            "Image Verifier Error: Owner LMS Signature Invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED,
            0x000b0003a,
            "Image Verifier Error: Vendor LMS Public Key Revoked"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO,
            0x000b003b,
            "Image Verifier Error: FMC Size Zero"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO,
            0x000b003c,
            "Image Verifier Error: Runtime Size Zero"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_LMS_PUB_KEY_IDX_MISMATCH,
            0x000b003d,
            "Image Verifier Error: Update Reset Vendor LMS Public Key Index Mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW,
            0x000b003e,
            "Image Verifier Error: FMC Load Address Image Size Arithmetic Overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW,
            0x000b003f,
            "Image Verifier Error: Runtime Load Address Image Size Arithmetic Overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_ENTRY_RANGE_ARITHMETIC_OVERFLOW,
            0x000b0040,
            "Image Verifier Error: TOC Entry Range Arithmetic Overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS,
            0x000b0041,
            "Image Verifier Error: Digest Out of Bounds"
        ),
        // Driver Error: LMS
        (
            DRIVER_LMS_INVALID_LMS_ALGO_TYPE,
            0x000c0001,
            "Driver Error: LMS Invalid LMS Algorithm Type"
        ),
        (
            DRIVER_LMS_INVALID_LMOTS_ALGO_TYPE,
            0x000c0002,
            "Driver Error: LMS Invalid LMOTS Algorithm Type"
        ),
        (
            DRIVER_LMS_INVALID_WINTERNITS_PARAM,
            0x000c0003,
            "Driver Error: LMS Invalid Winternits Parameter"
        ),
        (
            DRIVER_LMS_INVALID_PVALUE,
            0x000c0004,
            "Driver Error: LMS Invalid P-Value"
        ),
        (
            DRIVER_LMS_INVALID_HASH_WIDTH,
            0x000c0005,
            "Driver Error: LMS Invalid Hash Width"
        ),
        (
            DRIVER_LMS_INVALID_TREE_HEIGHT,
            0x000c0006,
            "Driver Error: LMS Invalid Tree Height"
        ),
        (
            DRIVER_LMS_INVALID_Q_VALUE,
            0x000c0007,
            "Driver Error: LMS Invalid Q Value"
        ),
        (
            DRIVER_LMS_INVALID_INDEX,
            0x000c0008,
            "Driver Error: LMS Invalid Index"
        ),
        (
            DRIVER_LMS_PATH_OUT_OF_BOUNDS,
            0x000c0009,
            "Driver Error: LMS Path Out of Bounds"
        ),
        (
            DRIVER_LMS_INVALID_SIGNATURE_LENGTH,
            0x000c000a,
            "Driver Error: LMS Invalid Signature Length"
        ),
        (
            DRIVER_LMS_INVALID_PUBLIC_KEY_LENGTH,
            0x000c000b,
            "Driver Error: LMS Invalid Public Key Length"
        ),
        (
            DRIVER_LMS_INVALID_SIGNATURE_DEPTH,
            0x000c000c,
            "Driver Error: LMS Invalid Signature Depth"
        ),
        (
            DRIVER_LMS_SIGNATURE_LMOTS_DOESNT_MATCH_PUBKEY_LMOTS,
            0x000c000d,
            "Driver Error: LMS Signature LMOTS Doesn't Match Public Key LMOTS"
        ),
        // CSRNG Errors
        (
            DRIVER_CSRNG_INSTANTIATE,
            0x000d0001,
            "Driver Error: CSRNG Instantiate"
        ),
        (
            DRIVER_CSRNG_UNINSTANTIATE,
            0x000d0002,
            "Driver Error: CSRNG Uninstantiate"
        ),
        (
            DRIVER_CSRNG_RESEED,
            0x000d0003,
            "Driver Error: CSRNG Reseed"
        ),
        (
            DRIVER_CSRNG_GENERATE,
            0x000d0004,
            "Driver Error: CSRNG Generate"
        ),
        (
            DRIVER_CSRNG_UPDATE,
            0x000d0005,
            "Driver Error: CSRNG Update"
        ),
        (
            DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED,
            0x000d0006,
            "Driver Error: CSRNG Other Health Check Failed"
        ),
        (
            DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED,
            0x000d0007,
            "Driver Error: CSRNG Repetition Count Health Check Failed"
        ),
        (
            DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED,
            0x000d0008,
            "Driver Error: CSRNG Adaptive Proportion Health Check Failed"
        ),
        (
            DRIVER_HANDOFF_INVALID_VAULT,
            0x000D100,
            "Driver Error: Handoff Invalid Vault"
        ),
        (
            DRIVER_HANDOFF_INVALID_KEY_ID,
            0x000D101,
            "Driver Error: Handoff Invalid Key ID"
        ),
        (
            DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY4,
            0x000D102,
            "Driver Error: Handoff Invalid Cold Reset Entry 4"
        ),
        (
            DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY48,
            0x000D103,
            "Driver Error: Handoff Invalid Cold Reset Entry 48"
        ),
        (
            DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY4,
            0x000D104,
            "Driver Error: Handoff Invalid Warm Reset Entry 4"
        ),
        (
            DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY48,
            0x000D105,
            "Driver Error: Handoff Invalid Warm Reset Entry 48"
        ),
        // Runtime Errors
        (RUNTIME_INTERNAL, 0x000E0001, "Runtime Error: Internal"),
        (
            RUNTIME_UNIMPLEMENTED_COMMAND,
            0x000E0002,
            "Runtime Error: Unimplemented Command"
        ),
        (
            RUNTIME_INSUFFICIENT_MEMORY,
            0x000E0003,
            "Runtime Error: Insufficient Memory"
        ),
        (
            RUNTIME_ECDSA_VERIFY_FAILED,
            0x000E0004,
            "Runtime Error: ECDSA Verify Failed"
        ),
        (
            RUNTIME_INVALID_CHECKSUM,
            0x000E0005,
            "Runtime Error: Invalid Checksum"
        ),
        (
            RUNTIME_HANDOFF_FHT_NOT_LOADED,
            0x000E0006,
            "Runtime Error: Handoff FHT Not Loaded"
        ),
        (
            RUNTIME_UNEXPECTED_UPDATE_RETURN,
            0x000E0007,
            "Runtime Error: Unexpected Update Return"
        ),
        (RUNTIME_SHUTDOWN, 0x000E0008, "Runtime Error: Shutdown"),
        (
            RUNTIME_MAILBOX_INVALID_PARAMS,
            0x000E0009,
            "Runtime Error: Mailbox Invalid Params"
        ),
        (RUNTIME_GLOBAL_NMI, 0x000E000A, "Runtime Error: Global NMI"),
        (
            RUNTIME_GLOBAL_EXCEPTION,
            0x000E000B,
            "Runtime Error: Global Exception"
        ),
        (
            RUNTIME_GLOBAL_PANIC,
            0x000E000C,
            "Runtime Error: Global Panic"
        ),
        (
            RUNTIME_HMAC_VERIFY_FAILED,
            0x000E000D,
            "Runtime Error: HMAC Verify Failed"
        ),
        (
            RUNTIME_INITIALIZE_DPE_FAILED,
            0x000E000E,
            "Runtime Error: Initialize DPE Failed"
        ),
        (
            RUNTIME_GET_IDEVID_CERT_FAILED,
            0x000E000F,
            "Runtime Error: Get IDEVID Cert Failed"
        ),
        (
            RUNTIME_CERT_CHAIN_CREATION_FAILED,
            0x000E0010,
            "Runtime Error: Cert Chain Creation Failed"
        ),
        (
            RUNTIME_SELF_TEST_IN_PROGRESS,
            0x000E0011,
            "Runtime Error: Self Test In Progress"
        ),
        (
            RUNTIME_SELF_TEST_NOT_STARTED,
            0x000E0012,
            "Runtime Error: Self Test Not Started"
        ),
        (
            RUNTIME_INVALID_FMC_SIZE,
            0x000E0013,
            "Runtime Error: Invalid FMC Size"
        ),
        (
            RUNTIME_INVALID_RUNTIME_SIZE,
            0x000E0014,
            "Runtime Error: Invalid Runtime Size"
        ),
        (
            RUNTIME_FMC_CERT_HANDOFF_FAILED,
            0x000E0015,
            "Runtime Error: FMC Cert Handoff Failed"
        ),
        (
            RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            0x000E0016,
            "Runtime Error: Incorrect Pauser Privilege Level"
        ),
        (
            RUNTIME_DPE_VALIDATION_FAILED,
            0x000E0017,
            "Runtime Error: DPE Validation Failed"
        ),
        (
            RUNTIME_UNKNOWN_RESET_FLOW,
            0x000E0018,
            "Runtime Error: Unknown Reset Flow"
        ),
        (
            RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED,
            0x000E0019,
            "Runtime Error: PL0 Used DPE Context Threshold Exceeded"
        ),
        (
            RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED,
            0x000E001A,
            "Runtime Error: PL1 Used DPE Context Threshold Exceeded"
        ),
        (
            RUNTIME_GLOBAL_WDT_EXPIRED,
            0x000E001B,
            "Runtime Error: Global WDT Expired"
        ),
        (
            RUNTIME_IDEV_CERT_POPULATION_FAILED,
            0x000E001C,
            "Runtime Error: IDEV Cert Population Failed"
        ),
        (
            RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED,
            0x000E001D,
            "Runtime Error: Add ROM Measurements to DPE Failed"
        ),
        (
            RUNTIME_TAGGING_FAILURE,
            0x000E001E,
            "Runtime Error: Tagging Failure"
        ),
        (
            RUNTIME_DUPLICATE_TAG,
            0x000E001F,
            "Runtime Error: Duplicate Tag"
        ),
        (
            RUNTIME_CONTEXT_ALREADY_TAGGED,
            0x000E0020,
            "Runtime Error: Context Already Tagged"
        ),
        (
            RUNTIME_ADD_VALID_PAUSER_MEASUREMENT_TO_DPE_FAILED,
            0x000E0021,
            "Runtime Error: Add Valid Pauser Measurement to DPE Failed"
        ),
        (
            RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE,
            0x000E0022,
            "Runtime Error: Mailbox API Response Data Length Too Large"
        ),
        (
            RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE,
            0x000E0023,
            "Runtime Error: Mailbox API Request Data Length Too Large"
        ),
        (
            RUNTIME_LDEVID_CERT_HANDOFF_FAILED,
            0x000E0024,
            "Runtime Error: LDEVID Cert Handoff Failed"
        ),
        (
            RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED,
            0x000E0025,
            "Runtime Error: Context Tags Validation Failed"
        ),
        (
            RUNTIME_COULD_NOT_GET_DPE_PROFILE,
            0x000E0026,
            "Runtime Error: Could Not Get DPE Profile"
        ),
        (
            RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
            0x000E0027,
            "Runtime Error: DPE Command Deserialization Failed"
        ),
        (
            RUNTIME_GET_LDEVID_CERT_FAILED,
            0x000E0028,
            "Runtime Error: Get LDEVID Cert Failed"
        ),
        (
            RUNTIME_GET_FMC_ALIAS_CERT_FAILED,
            0x000E0029,
            "Runtime Error: Get FMC Alias Cert Failed"
        ),
        (
            RUNTIME_GET_RT_ALIAS_CERT_FAILED,
            0x000E002A,
            "Runtime Error: Get RT Alias Cert Failed"
        ),
        (
            RUNTIME_CMD_BUSY_DURING_WARM_RESET,
            0x000E002B,
            "Runtime Error: Command Busy During Warm Reset"
        ),
        (
            RUNTIME_RT_SVN_HANDOFF_FAILED,
            0x000E002C,
            "Runtime Error: RT SVN Handoff Failed"
        ),
        (
            RUNTIME_RT_MIN_SVN_HANDOFF_FAILED,
            0x000E002D,
            "Runtime Error: RT Min SVN Handoff Failed"
        ),
        (
            RUNTIME_FMC_SVN_HANDOFF_FAILED,
            0x000E002E,
            "Runtime Error: FMC SVN Handoff Failed"
        ),
        (
            RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED,
            0x000E002F,
            "Runtime Error: Context Has Tag Validation Failed"
        ),
        (
            RUNTIME_LDEV_ID_CERT_TOO_BIG,
            0x000E0030,
            "Runtime Error: LDEV ID Cert Too Big"
        ),
        (
            RUNTIME_FMC_ALIAS_CERT_TOO_BIG,
            0x000E0031,
            "Runtime Error: FMC Alias Cert Too Big"
        ),
        (
            RUNTIME_RT_ALIAS_CERT_TOO_BIG,
            0x000E0032,
            "Runtime Error: RT Alias Cert Too Big"
        ),
        (
            RUNTIME_COMPUTE_RT_ALIAS_SN_FAILED,
            0x000E0033,
            "Runtime Error: Compute RT Alias SN Failed"
        ),
        (
            RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED,
            0x000E0034,
            "Runtime Error: RT Journey PCR Validation Failed"
        ),
        (
            RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT,
            0x000E0035,
            "Runtime Error: Unable to Find DPE Root Context"
        ),
        (
            RUNTIME_INCREMENT_PCR_RESET_MAX_REACHED,
            0x000E0036,
            "Runtime Error: Increment PCR Reset Max Reached"
        ),
        (
            RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
            0x000E0037,
            "Runtime Error: PL0 Used DPE Context Threshold Reached"
        ),
        (
            RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
            0x000E0038,
            "Runtime Error: PL1 Used DPE Context Threshold Reached"
        ),
        (
            RUNTIME_CDI_KV_HDL_HANDOFF_FAILED,
            0x000E0039,
            "Runtime Error: CDI KV HDL Handoff Failed"
        ),
        (
            RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED,
            0x000E003A,
            "Runtime Error: Priv Key KV HDL Handoff Failed"
        ),
        (
            RUNTIME_HASH_CHAIN_HANDOFF_FAILED,
            0x000E003B,
            "Runtime Error: Hash Chain Handoff Failed"
        ),
        (
            RUNTIME_PCR_RESERVED,
            0x000E003C,
            "Runtime Error: PCR Reserved"
        ),
        (
            RUNTIME_PCR_INVALID_INDEX,
            0x000E003D,
            "Runtime Error: PCR Invalid Index"
        ),
        (
            RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED,
            0x000E003E,
            "Runtime Error: DMTF Device Info Validation Failed"
        ),
        (
            RUNTIME_STORE_DMTF_DEVICE_INFO_FAILED,
            0x000E003F,
            "Runtime Error: Store DMTF Device Info Failed"
        ),
        (
            RUNTIME_CERTIFY_KEY_EXTENDED_FAILED,
            0x000E0040,
            "Runtime Error: Certify Key Extended Failed"
        ),
        (
            RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED,
            0x000E0041,
            "Runtime Error: DPE Response Serialization Failed"
        ),
        (
            RUNTIME_LMS_VERIFY_FAILED,
            0x000E0042,
            "Runtime Error: LMS Verify Failed"
        ),
        (
            RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM,
            0x000E0043,
            "Runtime Error: LMS Verify Invalid LMS Algorithm"
        ),
        (
            RUNTIME_LMS_VERIFY_INVALID_LMOTS_ALGORITHM,
            0x000E0044,
            "Runtime Error: LMS Verify Invalid LMOTS Algorithm"
        ),
        (
            RUNTIME_INVALID_AUTH_MANIFEST_MARKER,
            0x000E0045,
            "Runtime Error: Invalid Auth Manifest Marker"
        ),
        (
            RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH,
            0x000E0046,
            "Runtime Error: Auth Manifest Preamble Size Mismatch"
        ),
        (
            RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
            0x000E0047,
            "Runtime Error: Auth Manifest Vendor ECC Signature Invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
            0x000E0048,
            "Runtime Error: Auth Manifest Vendor LMS Signature Invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
            0x000E0049,
            "Runtime Error: Auth Manifest Owner ECC Signature Invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            0x000E004A,
            "Runtime Error: Auth Manifest Owner LMS Signature Invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN,
            0x000E004B,
            "Runtime Error: Auth Manifest Preamble Size Less Than Minimum"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE,
            0x000E004C,
            "Runtime Error: Auth Manifest Image Metadata List Invalid Size"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
            0x000E004D,
            "Runtime Error: Auth Manifest Image Metadata List Invalid Entry Count"
        ),
        (
            RUNTIME_AUTH_AND_STASH_UNSUPPORTED_IMAGE_SOURCE,
            0x000E004E,
            "Runtime Error: Auth and Stash Unsupported Image Source"
        ),
        (
            RUNTIME_CMD_RESERVED_PAUSER,
            0x000E004F,
            "Runtime Error: Command Reserved Pauser"
        ),
        (
            RUNTIME_AUTH_AND_STASH_MEASUREMENT_DPE_ERROR,
            0x000E0050,
            "Runtime Error: Auth and Stash Measurement DPE Error"
        ),
        (
            RUNTIME_GET_IDEV_ID_UNPROVISIONED,
            0x000E0051,
            "Runtime Error: Get IDEV ID Unprovisioned"
        ),
        (
            RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM,
            0x000E0052,
            "Runtime Error: Get IDEV ID Unsupported ROM"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_DUPLICATE_FIRMWARE_ID,
            0x000E0053,
            "Runtime Error: Auth Manifest Image Metadata List Duplicate Firmware ID"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
            0x000E0054,
            "Runtime Error: Sign with Exported ECDSA Key Derivation Failed"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED,
            0x000E0055,
            "Runtime Error: Sign with Exported ECDSA Signature Failed"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_DIGEST,
            0x000E0056,
            "Runtime Error: Sign with Exported ECDSA Invalid Digest"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE,
            0x000E0057,
            "Runtime Error: Sign with Exported ECDSA Invalid Signature"
        ),
        (
            RUNTIME_GET_FMC_CSR_UNPROVISIONED,
            0x000E0058,
            "Runtime Error: Get FMC CSR Unprovisioned"
        ),
        (
            RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC,
            0x000E0059,
            "Runtime Error: Get FMC CSR Unsupported FMC"
        ),
        (
            RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
            0x000E005A,
            "Runtime Error: Revoke Exported CDI Handle Not Found"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_MIN,
            0x000E005B,
            "Runtime Error: Reallocate DPE context requested less than the minimum PL0 contexts"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_GREATER_THAN_MAX,
            0x000E005C,
            "Runtime Error: Reallocate DPE context requested greater than the maximum PL0 contexts"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_USED,
            0x000E005D,
            "Runtime Error: Reallocate DPE context requested fewer PL0 contexts than are used currently"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL1_LESS_THAN_USED,
            0x000E005E,
            "Runtime Error: Reallocate DPE context requested fewer PL1 contexts than are used currently"
        ),
        // FMC Errors
        (FMC_GLOBAL_NMI, 0x000F0001, "FMC Error: Global NMI"),
        (
            FMC_GLOBAL_EXCEPTION,
            0x000F0002,
            "FMC Error: Global Exception"
        ),
        (FMC_GLOBAL_PANIC, 0x000F0003, "FMC Error: Global Panic"),
        (
            FMC_HANDOFF_INVALID_PARAM,
            0x000F0004,
            "FMC Error: Handoff Invalid Parameter"
        ),
        (
            FMC_RT_ALIAS_DERIVE_FAILURE,
            0x000F0005,
            "FMC Error: RT Alias Derive Failure"
        ),
        (
            FMC_RT_ALIAS_CERT_VERIFY,
            0x000F0006,
            "FMC Error: RT Alias Certificate Verification"
        ),
        (
            FMC_RT_ALIAS_TBS_SIZE_EXCEEDED,
            0x000F0007,
            "FMC Error: RT Alias TBS Size Exceeded"
        ),
        (
            FMC_CDI_KV_COLLISION,
            0x000F0008,
            "FMC Error: CDI KV Collision"
        ),
        (
            FMC_ALIAS_KV_COLLISION,
            0x000F0009,
            "FMC Error: Alias KV Collision"
        ),
        (
            FMC_GLOBAL_PCR_LOG_EXHAUSTED,
            0x000F000A,
            "FMC Error: Global PCR Log Exhausted"
        ),
        (
            ADDRESS_NOT_IN_ICCM,
            0x000F000B,
            "FMC Error: Address Not in ICCM"
        ),
        (
            FMC_HANDOFF_NOT_READY_FOR_RT,
            0x000F000C,
            "FMC Error: Handoff Not Ready for RT"
        ),
        (
            FMC_GLOBAL_WDT_EXPIRED,
            0x000F000D,
            "FMC Error: Global WDT Expired"
        ),
        (FMC_UNKNOWN_RESET, 0x000F000E, "FMC Error: Unknown Reset"),
        // FMC Alias CSR Errors
        (
            FMC_ALIAS_CSR_BUILDER_INIT_FAILURE,
            0x000F000F,
            "FMC Alias CSR Builder Init Failure"
        ),
        (
            FMC_ALIAS_CSR_BUILDER_BUILD_FAILURE,
            0x000F0010,
            "FMC Alias CSR Builder Build Failure"
        ),
        (FMC_ALIAS_INVALID_CSR, 0x000F0011, "FMC Alias Invalid CSR"),
        (
            FMC_ALIAS_CSR_VERIFICATION_FAILURE,
            0x000F0012,
            "FMC Alias CSR Verification Failure"
        ),
        (FMC_ALIAS_CSR_OVERFLOW, 0x000F0013, "FMC Alias CSR Overflow"),
        (
            DRIVER_TRNG_EXT_TIMEOUT,
            0x00100001,
            "TRNG_EXT Error: Timeout"
        ),
        // SOC_IFC driver Errors
        (
            DRIVER_SOC_IFC_INVALID_TIMER_CONFIG,
            0x00100002,
            "SOC_IFC Driver Error: Invalid Timer Configuration"
        ),
        // Bounded address Errors
        (
            ADDRESS_MISALIGNED,
            0x00110000,
            "Bounded Address Error: Address Misaligned"
        ),
        (
            ADDRESS_NOT_IN_ROM,
            0x00110001,
            "Bounded Address Error: Address Not in ROM"
        ),
        // Initial Device ID Errors
        (
            ROM_IDEVID_CSR_BUILDER_INIT_FAILURE,
            0x01000001,
            "ROM Initial Device ID Error: CSR Builder Init Failure"
        ),
        (
            ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE,
            0x01000002,
            "ROM Initial Device ID Error: CSR Builder Build Failure"
        ),
        (
            ROM_IDEVID_INVALID_CSR,
            0x01000003,
            "ROM Initial Device ID Error: Invalid CSR"
        ),
        (
            ROM_IDEVID_CSR_VERIFICATION_FAILURE,
            0x01000004,
            "ROM Initial Device ID Error: CSR Verification Failure"
        ),
        (
            ROM_IDEVID_CSR_OVERFLOW,
            0x01000005,
            "ROM Initial Device ID Error: CSR Overflow"
        ),
        // ROM Local Device ID Errors
        (
            ROM_LDEVID_CSR_VERIFICATION_FAILURE,
            0x01010001,
            "ROM Local Device ID Error: CSR Verification Failure"
        ),
        // Firmware Processor Errors
        (
            FW_PROC_MANIFEST_READ_FAILURE,
            0x01020001,
            "Firmware Processor Error: Manifest Read Failure"
        ),
        (
            FW_PROC_INVALID_IMAGE_SIZE,
            0x01020002,
            "Firmware Processor Error: Invalid Image Size"
        ),
        (
            FW_PROC_MAILBOX_STATE_INCONSISTENT,
            0x01020003,
            "Firmware Processor Error: Mailbox State Inconsistent"
        ),
        (
            FW_PROC_MAILBOX_INVALID_COMMAND,
            0x01020004,
            "Firmware Processor Error: Mailbox Invalid Command"
        ),
        (
            FW_PROC_MAILBOX_INVALID_CHECKSUM,
            0x01020005,
            "Firmware Processor Error: Mailbox Invalid Checksum"
        ),
        (
            FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH,
            0x01020006,
            "Firmware Processor Error: Mailbox Invalid Request Length"
        ),
        (
            FW_PROC_MAILBOX_PROCESS_FAILURE,
            0x01020007,
            "Firmware Processor Error: Mailbox Process Failure"
        ),
        (
            FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT,
            0x01020008,
            "Firmware Processor Error: Mailbox Stash Measurement Max Limit"
        ),
        (
            FW_PROC_MAILBOX_RESERVED_PAUSER,
            0x01020009,
            "Firmware Processor Error: Mailbox Reserved Pauser"
        ),
        (
            FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
            0x0102000A,
            "Firmware Processor Error: Mailbox Get IDEV CSR Unprovisioned CSR"
        ),
        // FMC Alias Layer : Certificate Verification Failure.
        (
            FMC_ALIAS_CERT_VERIFY,
            0x01030001,
            "FMC Alias Layer: Certificate Verification Failure"
        ),
        // Update Reset Errors
        (
            ROM_UPDATE_RESET_FLOW_MANIFEST_READ_FAILURE,
            0x01040002,
            "ROM Update Reset Flow: Manifest Read Failure"
        ),
        (
            ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND,
            0x01040003,
            "ROM Update Reset Flow: Invalid Firmware Command"
        ),
        (
            ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE,
            0x01040004,
            "ROM Update Reset Flow: Mailbox Access Failure"
        ),
        (
            ROM_UPDATE_RESET_READ_FHT_FAILURE,
            0x01040005,
            "ROM Update Reset Flow: Read FHT Failure"
        ),
        // Warm Reset Errors
        (
            ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET,
            0x01040010,
            "ROM Warm Reset Unsuccessful: Previous Cold Reset"
        ),
        (
            ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET,
            0x01040011,
            "ROM Warm Reset Unsuccessful: Previous Update Reset"
        ),
        // Unknown Reset Error
        (ROM_UNKNOWN_RESET_FLOW, 0x01040020, "ROM Unknown Reset Flow"),
        // ROM CFI Errors
        (
            ROM_CFI_PANIC_UNKNOWN,
            0x1040050,
            "ROM CFI Error: Panic Unknown"
        ),
        (
            ROM_CFI_PANIC_COUNTER_CORRUPT,
            0x1040051,
            "ROM CFI Error: Panic Counter Corrupt"
        ),
        (
            ROM_CFI_PANIC_COUNTER_OVERFLOW,
            0x1040052,
            "ROM CFI Error: Panic Counter Overflow"
        ),
        (
            ROM_CFI_PANIC_COUNTER_UNDERFLOW,
            0x1040053,
            "ROM CFI Error: Panic Counter Underflow"
        ),
        (
            ROM_CFI_PANIC_COUNTER_MISMATCH,
            0x1040054,
            "ROM CFI Error: Panic Counter Mismatch"
        ),
        (
            ROM_CFI_PANIC_ASSERT_EQ_FAILURE,
            0x1040055,
            "ROM CFI Error: Panic Assert Equal Failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_NE_FAILURE,
            0x1040056,
            "ROM CFI Error: Panic Assert Not Equal Failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_GT_FAILURE,
            0x1040057,
            "ROM CFI Error: Panic Assert Greater Than Failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_LT_FAILURE,
            0x1040058,
            "ROM CFI Error: Panic Assert Less Than Failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_GE_FAILURE,
            0x1040059,
            "ROM CFI Error: Panic Assert Greater or Equal Failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_LE_FAILURE,
            0x104005A,
            "ROM CFI Error: Panic Assert Less or Equal Failure"
        ),
        (
            ROM_CFI_PANIC_TRNG_FAILURE,
            0x104005B,
            "ROM CFI Error: Panic TRNG Failure"
        ),
        (
            ROM_CFI_PANIC_UNEXPECTED_MATCH_BRANCH,
            0x104005C,
            "ROM CFI Error: Panic Unexpected Match Branch"
        ),
        (
            ROM_CFI_PANIC_FAKE_TRNG_USED_WITH_DEBUG_LOCK,
            0x104005D,
            "ROM CFI Error: Panic Fake TRNG Used with Debug Lock"
        ),
        // ROM Global Errors
        (ROM_GLOBAL_NMI, 0x01050001, "ROM Global Error: NMI"),
        (
            ROM_GLOBAL_EXCEPTION,
            0x01050002,
            "ROM Global Error: Exception"
        ),
        (ROM_GLOBAL_PANIC, 0x01050003, "ROM Global Error: Panic"),
        (
            ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID,
            0x01050004,
            "ROM Global Error: PCR Log Invalid Entry ID"
        ),
        (
            ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH,
            0x01050005,
            "ROM Global Error: PCR Log Unsupported Data Length"
        ),
        (
            ROM_GLOBAL_PCR_LOG_EXHAUSTED,
            0x01050006,
            "ROM Global Error: PCR Log Exhausted"
        ),
        (
            ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID,
            0x01050007,
            "ROM Global Error: Fuse Log Invalid Entry ID"
        ),
        (
            ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH,
            0x01050008,
            "ROM Global Error: Fuse Log Unsupported Data Length"
        ),
        (
            ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE,
            0x01050009,
            "ROM Global Error: Unsupported LDEVID TBS Size"
        ),
        (
            ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE,
            0x0105000A,
            "ROM Global Error: Unsupported FMCALIAS TBS Size"
        ),
        (
            ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION,
            0x0105000B,
            "ROM Global Error: Fake ROM in Production"
        ),
        (
            ROM_GLOBAL_WDT_EXPIRED,
            0x0105000C,
            "ROM Global Error: WDT Expired"
        ),
        (
            ROM_GLOBAL_MEASUREMENT_LOG_EXHAUSTED,
            0x0105000D,
            "ROM Global Error: Measurement Log Exhausted"
        ),
        (
            ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT,
            0x0105000F,
            "ROM Global Error: FIPS Hooks ROM Exit"
        ),
        (
            ROM_GLOBAL_X509_DIGEST_CONVERSION_FAILURE,
            0x01050010,
            "ROM Global Error: X509 Digest Conversion Failure"
        ),
        // ROM KAT Errors
        (
            KAT_SHA256_DIGEST_FAILURE,
            0x90010001,
            "KAT Error: SHA256 Digest Failure"
        ),
        (
            KAT_SHA256_DIGEST_MISMATCH,
            0x90010002,
            "KAT Error: SHA256 Digest Mismatch"
        ),
        (
            KAT_SHA384_DIGEST_FAILURE,
            0x90020001,
            "KAT Error: SHA384 Digest Failure"
        ),
        (
            KAT_SHA384_DIGEST_MISMATCH,
            0x90020002,
            "KAT Error: SHA384 Digest Mismatch"
        ),
        (
            KAT_HMAC384_FAILURE,
            0x90030001,
            "KAT Error: HMAC384 Failure"
        ),
        (
            KAT_HMAC384_TAG_MISMATCH,
            0x90030002,
            "KAT Error: HMAC384 Tag Mismatch"
        ),
        // 0x90040001 was KAT_ECC384_SIGNATURE_GENERATE_FAILURE
        // 0x90040002 was KAT_ECC384_SIGNATURE_VERIFY_FAILURE
        (
            KAT_ECC384_SIGNATURE_MISMATCH,
            0x90040003,
            "KAT Error: ECC384 Signature Mismatch"
        ),
        (
            KAT_ECC384_KEY_PAIR_GENERATE_FAILURE,
            0x90040004,
            "KAT Error: ECC384 Key Pair Generate Failure"
        ),
        (
            KAT_ECC384_KEY_PAIR_VERIFY_FAILURE,
            0x90040005,
            "KAT Error: ECC384 Key Pair Verify Failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE,
            0x90050001,
            "KAT Error: SHA2_512_384_ACC Digest Start Operation Failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_FAILURE,
            0x90050002,
            "KAT Error: SHA2_512_384_ACC Digest Failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_MISMATCH,
            0x90050003,
            "KAT Error: SHA2_512_384_ACC Digest Mismatch"
        ),
        (
            KAT_SHA1_DIGEST_FAILURE,
            0x90060001,
            "KAT Error: SHA1 Digest Failure"
        ),
        (
            KAT_SHA1_DIGEST_MISMATCH,
            0x90060002,
            "KAT Error: SHA1 Digest Mismatch"
        ),
        (
            KAT_LMS_DIGEST_FAILURE,
            0x90070001,
            "KAT Error: LMS Digest Failure"
        ),
        (
            KAT_LMS_DIGEST_MISMATCH,
            0x90070002,
            "KAT Error: LMS Digest Mismatch"
        ),
        (
            ROM_INTEGRITY_FAILURE,
            0x90080001,
            "ROM Error: Integrity Failure"
        ),
        // TODO: What base value is right for this?
        // FIPS Hooks
        (
            FIPS_HOOKS_INJECTED_ERROR,
            0x90100000,
            "FIPS Hooks: Injected Error"
        ),
    ];
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

impl TryFrom<u32> for CaliptraError {
    type Error = TryFromIntError;
    fn try_from(val: u32) -> Result<Self, TryFromIntError> {
        match NonZeroU32::try_from(val) {
            Ok(val) => Ok(CaliptraError(val)),
            Err(err) => Err(err),
        }
    }
}

pub type CaliptraResult<T> = Result<T, CaliptraError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_try_from() {
        assert!(CaliptraError::try_from(0).is_err());
        assert_eq!(
            Ok(CaliptraError::DRIVER_SHA256_INVALID_STATE),
            CaliptraError::try_from(0x00020001)
        );
    }

    #[test]
    fn test_error_constants_uniqueness() {
        let constants = CaliptraError::all_constants();
        let mut error_values = HashSet::new();
        let mut duplicates = Vec::new();

        for (name, value) in constants {
            if !error_values.insert(value) {
                duplicates.push((name, value));
            }
        }

        assert!(
            duplicates.is_empty(),
            "Found duplicate error codes: {:?}",
            duplicates
        );
    }
}
