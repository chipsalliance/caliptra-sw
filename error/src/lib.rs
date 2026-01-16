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

    // Use the macro to define all error constants
    define_error_constants![
        (
            DRIVER_BAD_DATASTORE_VAULT_TYPE,
            0x00010001,
            "Bad datastore vault type"
        ),
        (
            DRIVER_BAD_DATASTORE_REG_TYPE,
            0x00010002,
            "Bad datastore register type"
        ),
        (CALIPTRA_INTERNAL, 0x00010003, "Internal error"),
        (
            DRIVER_SHA256_INVALID_STATE,
            0x00020001,
            "SHA256 invalid state"
        ),
        (
            DRIVER_SHA256_MAX_DATA,
            0x00020002,
            "SHA256 max data exceeded"
        ),
        (
            DRIVER_SHA256_INVALID_SLICE,
            0x00020003,
            "SHA256 invalid slice"
        ),
        (
            DRIVER_SHA256_INDEX_OUT_OF_BOUNDS,
            0x00020004,
            "SHA256 index out of bounds"
        ),
        (
            DRIVER_SHA2_512_384_READ_DATA_KV_READ,
            0x00030001,
            "Driver Error: SHA2_512_384 read data KV read"
        ),
        (
            DRIVER_SHA2_512_384_READ_DATA_KV_WRITE,
            0x00030002,
            "Driver Error: SHA2_512_384 read data KV write"
        ),
        (
            DRIVER_SHA2_512_384_READ_DATA_KV_UNKNOWN,
            0x00030003,
            "Driver Error: SHA2_512_384 read data KV unknown"
        ),
        (
            DRIVER_SHA2_512_384_INVALID_STATE_ERR,
            0x00030007,
            "Driver Error: SHA2_512_384 invalid state"
        ),
        (
            DRIVER_SHA2_512_384_MAX_DATA_ERR,
            0x00030008,
            "Driver Error: SHA2_512_384 max data exceeded"
        ),
        (
            DRIVER_SHA2_512_384_INVALID_KEY_SIZE,
            0x00030009,
            "Driver Error: SHA2_512_384 invalid key size"
        ),
        (
            DRIVER_SHA2_512_384_INVALID_SLICE,
            0x0003000A,
            "Driver Error: SHA2_512_384 invalid slice"
        ),
        (
            DRIVER_SHA2_512_384_INDEX_OUT_OF_BOUNDS,
            0x0003000B,
            "Driver Error: SHA2_512_384 index out of bounds"
        ),
        (
            DRIVER_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE,
            0x0003000C,
            "Driver Error: SHA2_512_384 SHA2_512_384_ACC digest start op failure"
        ),
        (
            DRIVER_SHA2_512_384ACC_UNEXPECTED_ACQUIRED_LOCK_STATE,
            0x00038000,
            "Driver Error: SHA2_512_384ACC unexpected acquired lock state"
        ),
        (
            DRIVER_HMAC_READ_KEY_KV_READ,
            0x00040001,
            "Driver Error: HMAC read key KV read"
        ),
        (
            DRIVER_HMAC_READ_KEY_KV_WRITE,
            0x00040002,
            "Driver Error: HMAC read key KV write"
        ),
        (
            DRIVER_HMAC_READ_KEY_KV_UNKNOWN,
            0x00040003,
            "Driver Error: HMAC read key KV unknown"
        ),
        (
            DRIVER_HMAC_READ_DATA_KV_READ,
            0x00040004,
            "Driver Error: HMAC read data KV read"
        ),
        (
            DRIVER_HMAC_READ_DATA_KV_WRITE,
            0x00040005,
            "Driver Error: HMAC read data KV write"
        ),
        (
            DRIVER_HMAC_READ_DATA_KV_UNKNOWN,
            0x00040006,
            "Driver Error: HMAC read data KV unknown"
        ),
        (
            DRIVER_HMAC_WRITE_TAG_KV_READ,
            0x00040007,
            "Driver Error: HMAC write tag KV read"
        ),
        (
            DRIVER_HMAC_WRITE_TAG_KV_WRITE,
            0x00040008,
            "Driver Error: HMAC write tag KV write"
        ),
        (
            DRIVER_HMAC_WRITE_TAG_KV_UNKNOWN,
            0x00040009,
            "Driver Error: HMAC write tag KV unknown"
        ),
        (
            DRIVER_HMAC_INVALID_STATE,
            0x0004000b,
            "Driver Error: HMAC invalid state"
        ),
        (
            DRIVER_HMAC_MAX_DATA,
            0x0004000c,
            "Driver Error: HMAC max data exceeded"
        ),
        (
            DRIVER_HMAC_INVALID_SLICE,
            0x0004000d,
            "Driver Error: HMAC invalid slice"
        ),
        (
            DRIVER_HMAC_INDEX_OUT_OF_BOUNDS,
            0x0004000e,
            "Driver Error: HMAC index out of bounds"
        ),
        (
            DRIVER_HKDF_SALT_TOO_LONG,
            0x0004000f,
            "Driver Error: HKDF salt is too large"
        ),
        (
            DRIVER_AES_READ_KEY_KV_READ,
            0x00040010,
            "Driver Error: AES read key KV read"
        ),
        (
            DRIVER_CMAC_KDF_INVALID_SLICE,
            0x00040011,
            "Driver Error: CMAC KDF invalid slice"
        ),
        (
            DRIVER_CMAC_KDF_INVALID_ROUNDS,
            0x00040012,
            "Driver Error: CMAC KDF invalid number of rounds"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_READ,
            0x00050001,
            "Driver Error: ECC384 read seed KV read"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_WRITE,
            0x00050002,
            "Driver Error: ECC384 read seed KV write"
        ),
        (
            DRIVER_ECC384_READ_SEED_KV_UNKNOWN,
            0x00050003,
            "Driver Error: ECC384 read seed KV unknown"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_READ,
            0x00050004,
            "Driver Error: ECC384 write private key KV read"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_WRITE,
            0x00050005,
            "Driver Error: ECC384 write private key KV write"
        ),
        (
            DRIVER_ECC384_WRITE_PRIV_KEY_KV_UNKNOWN,
            0x00050006,
            "Driver Error: ECC384 write private key KV unknown"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_READ,
            0x00050007,
            "Driver Error: ECC384 read private key KV read"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_WRITE,
            0x00050008,
            "Driver Error: ECC384 read private key KV write"
        ),
        (
            DRIVER_ECC384_READ_PRIV_KEY_KV_UNKNOWN,
            0x00050009,
            "Driver Error: ECC384 read private key KV unknown"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_READ,
            0x0005000a,
            "Driver Error: ECC384 read data KV read"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_WRITE,
            0x0005000b,
            "Driver Error: ECC384 read data KV write"
        ),
        (
            DRIVER_ECC384_READ_DATA_KV_UNKNOWN,
            0x0005000c,
            "Driver Error: ECC384 read data KV unknown"
        ),
        (
            DRIVER_ECC384_KEYGEN_PAIRWISE_CONSISTENCY_FAILURE,
            0x0005000d,
            "Driver Error: ECC384 key generation pairwise consistency failure"
        ),
        (
            DRIVER_ECC384_SIGN_VALIDATION_FAILED,
            0x0005000e,
            "Driver Error: ECC384 sign validation failed"
        ),
        (
            DRIVER_ECC384_SCALAR_RANGE_CHECK_FAILED,
            0x0005000f,
            "Driver Error: ECC384 scalar range check failed"
        ),
        (
            DRIVER_ECC384_KEYGEN_BAD_USAGE,
            0x00050010,
            "Driver Error: ECC384 key generation bad usage"
        ),
        (
            DRIVER_ECC384_HW_ERROR,
            0x00050011,
            "Driver Error: ECC384 hardware error"
        ),
        (
            DRIVER_MLDSA87_READ_SEED_KV_READ,
            0x00058000,
            "Driver Error: MLDSA87 read seed KV read"
        ),
        (
            DRIVER_MLDSA87_READ_SEED_KV_WRITE,
            0x00058001,
            "Driver Error: MLDSA87 read seed KV write"
        ),
        (
            DRIVER_MLDSA87_READ_SEED_KV_UNKNOWN,
            0x00058002,
            "Driver Error: MLDSA87 read seed KV unknown"
        ),
        (
            DRIVER_MLDSA87_HW_ERROR,
            0x00058003,
            "Driver Error: MLDSA87 hardware error"
        ),
        (
            DRIVER_MLDSA87_SIGN_VALIDATION_FAILED,
            0x00058004,
            "Driver Error: MLDSA87 sign validation failed"
        ),
        (
            DRIVER_MLDSA87_KEY_GEN_SEED_BAD_USAGE,
            0x00058005,
            "Driver Error: MLDSA87 key generation seed bad usage"
        ),
        (
            DRIVER_MLDSA87_UNSUPPORTED_SIGNATURE,
            0x00058006,
            "Driver Error: MLDSA87 signature is not supported"
        ),
        (
            DRIVER_MLKEM_READ_SEED_KV_READ,
            0x00059000,
            "Driver Error: ML-KEM read seed KV read"
        ),
        (
            DRIVER_MLKEM_READ_SEED_KV_WRITE,
            0x00059001,
            "Driver Error: ML-KEM read seed KV write"
        ),
        (
            DRIVER_MLKEM_READ_SEED_KV_UNKNOWN,
            0x00059002,
            "Driver Error: ML-KEM read seed KV unknown"
        ),
        (
            DRIVER_MLKEM_HW_ERROR,
            0x00059003,
            "Driver Error: ML-KEM hardware error"
        ),
        (
            DRIVER_MLKEM_READ_MSG_KV_READ,
            0x00059004,
            "Driver Error: ML-KEM read message KV read"
        ),
        (
            DRIVER_MLKEM_READ_MSG_KV_WRITE,
            0x00059005,
            "Driver Error: ML-KEM read message KV write"
        ),
        (
            DRIVER_MLKEM_READ_MSG_KV_UNKNOWN,
            0x00059006,
            "Driver Error: ML-KEM read message KV unknown"
        ),
        (
            DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE,
            0x00060001,
            "Driver Error: KV erase use lock set failure"
        ),
        (
            DRIVER_KV_ERASE_WRITE_LOCK_SET_FAILURE,
            0x00060002,
            "Driver Error: KV erase write lock set failure"
        ),
        (
            DRIVER_PCR_BANK_ERASE_WRITE_LOCK_SET_FAILURE,
            0x00070001,
            "Driver Error: PCR bank erase write lock set failure"
        ),
        (
            DRIVER_RECOVERY_INVALID_CMS_TYPE,
            0x00052000,
            "Recovery register interface driver: Invalid CMS type"
        ),
        (
            DRIVER_RECOVERY_INVALID_CMS,
            0x00052001,
            "Recovery register interface driver: Invalid CMS"
        ),
        (
            DRIVER_MAILBOX_INVALID_STATE,
            0x00080001,
            "Mailbox Error: Invalid state"
        ),
        (
            DRIVER_MAILBOX_INVALID_DATA_LEN,
            0x00080002,
            "Mailbox Error: Invalid data length"
        ),
        (
            DRIVER_MAILBOX_ENQUEUE_ERR,
            0x00080004,
            "Mailbox Error: Enqueue error"
        ),
        (
            DRIVER_MAILBOX_UNCORRECTABLE_ECC,
            0x00080005,
            "Mailbox Error: Uncorrectable ECC"
        ),
        (
            DRIVER_SHA2_512_384ACC_INDEX_OUT_OF_BOUNDS,
            0x00090003,
            "SHA2_512_384ACC Error: Index out of bounds"
        ),
        (
            DRIVER_SHA1_INVALID_STATE,
            0x000a0001,
            "SHA1 Error: Invalid state"
        ),
        (
            DRIVER_SHA1_MAX_DATA,
            0x000a0002,
            "SHA1 Error: Max data exceeded"
        ),
        (
            DRIVER_SHA1_INVALID_SLICE,
            0x000a0003,
            "SHA1 Error: Invalid slice"
        ),
        (
            DRIVER_SHA1_INDEX_OUT_OF_BOUNDS,
            0x000a0004,
            "SHA1 Error: Index out of bounds"
        ),
        (
            DRIVER_OCP_LOCK_COLD_RESET_INVALID_HEK_SEED,
            0x000b0000,
            "OCP LOCK: Invalid HEK Seed state"
        ),
        (
            IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH,
            0x000b0001,
            "Image Verifier Error: Manifest marker mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH,
            0x000b0002,
            "Image Verifier Error: Manifest size mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID,
            0x000b0003,
            "Image Verifier Error: Vendor public key digest invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE,
            0x000b0004,
            "Image Verifier Error: Vendor public key digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH,
            0x000b0005,
            "Image Verifier Error: Vendor public key digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE,
            0x000b0006,
            "Image Verifier Error: Owner public key digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH,
            0x000b0007,
            "Image Verifier Error: Owner public key digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS,
            0x000b0008,
            "Image Verifier Error: Vendor ECC public key index out of bounds"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED,
            0x000b0009,
            "Image Verifier Error: Vendor ECC public key revoked"
        ),
        (
            IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE,
            0x000b000a,
            "Image Verifier Error: Header digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE,
            0x000b000b,
            "Image Verifier Error: Vendor ECC verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID,
            0x000b000c,
            "Image Verifier Error: Vendor ECC signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH,
            0x000b000d,
            "Image Verifier Error: Vendor ECC public key index mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE,
            0x000b000e,
            "Image Verifier Error: Owner ECC verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID,
            0x000b000f,
            "Image Verifier Error: Owner ECC signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID,
            0x000b0010,
            "Image Verifier Error: TOC entry count invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURE,
            0x000b0011,
            "Image Verifier Error: TOC digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH,
            0x000b0012,
            "Image Verifier Error: TOC digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE,
            0x000b0013,
            "Image Verifier Error: FMC digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH,
            0x000b0014,
            "Image Verifier Error: FMC digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE,
            0x000b0015,
            "Image Verifier Error: Runtime digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
            0x000b0016,
            "Image Verifier Error: Runtime digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP,
            0x000b0017,
            "Image Verifier Error: FMC runtime overlap"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER,
            0x000b0018,
            "Image Verifier Error: FMC runtime incorrect order"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG,
            0x000b0019,
            "Image Verifier Error: Owner ECC public key invalid arg"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG,
            0x000b001a,
            "Image Verifier Error: Owner ECC signature invalid arg"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INVALID_ARG,
            0x000b001b,
            "Image Verifier Error: Vendor ECC public key invalid arg"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG,
            0x000b001c,
            "Image Verifier Error: Vendor ECC signature invalid arg"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE,
            0x000b001d,
            "Image Verifier Error: Update reset owner digest failure"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_ECC_PUB_KEY_IDX_MISMATCH,
            0x000b001e,
            "Image Verifier Error: Update reset vendor ECC public key index mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH,
            0x000b001f,
            "Image Verifier Error: Update reset FMC digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID,
            0x000b0021,
            "Image Verifier Error: FMC load address invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED,
            0x000b0022,
            "Image Verifier Error: FMC load address unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID,
            0x000b0023,
            "Image Verifier Error: FMC entry point invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED,
            0x000b0024,
            "Image Verifier Error: FMC entry point unaligned"
        ),
        // 0x000b0025 (deprecated) was IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED
        // 0x000b0026 (deprecated) was IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED
        // 0x000b0027 (deprecated) was IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID,
            0x000b0028,
            "Image Verifier Error: Runtime load address invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED,
            0x000b0029,
            "Image Verifier Error: Runtime load address unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID,
            0x000b002a,
            "Image Verifier Error: Runtime entry point invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED,
            0x000b002b,
            "Image Verifier Error: Runtime entry point unaligned"
        ),
        (
            IMAGE_VERIFIER_ERR_FIRMWARE_SVN_GREATER_THAN_MAX_SUPPORTED,
            0x000b002c,
            "Image Verifier Error: Firmware SVN greater than max supported"
        ),
        // 0x000b002d (deprecated) was IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_MIN_SUPPORTED
        (
            IMAGE_VERIFIER_ERR_FIRMWARE_SVN_LESS_THAN_FUSE,
            0x000b002e,
            "Image Verifier Error: Firmware SVN less than fuse"
        ),
        (
            IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE,
            0x000b002f,
            "Image Verifier Error: Image length more than bundle size"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_MISMATCH,
            0x000b0030,
            "Image Verifier Error: Vendor PQC public key index mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE,
            0x000b0031,
            "Image Verifier Error: Vendor LMS verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_INDEX_OUT_OF_BOUNDS,
            0x000b0032,
            "Image Verifier Error: Vendor PQC public key index out of bounds"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID,
            0x000b0033,
            "Image Verifier Error: Vendor LMS signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP,
            0x000b0034,
            "Image Verifier Error: FMC runtime load address overlap"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_LMS_VERIFY_FAILURE,
            0x000b0036,
            "Image Verifier Error: Owner LMS verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID,
            0x000b0038,
            "Image Verifier Error: Owner LMS signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_REVOKED,
            0x000b003a,
            "Image Verifier Error: Vendor PQC public key revoked"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO,
            0x000b003b,
            "Image Verifier Error: FMC size zero"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO,
            0x000b003c,
            "Image Verifier Error: Runtime size zero"
        ),
        (
            IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PQC_PUB_KEY_IDX_MISMATCH,
            0x000b003d,
            "Image Verifier Error: Update reset vendor PQC public key index mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_FMC_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW,
            0x000b003e,
            "Image Verifier Error: FMC load address image size arithmetic overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDRESS_IMAGE_SIZE_ARITHMETIC_OVERFLOW,
            0x000b003f,
            "Image Verifier Error: Runtime load address image size arithmetic overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_TOC_ENTRY_RANGE_ARITHMETIC_OVERFLOW,
            0x000b0040,
            "Image Verifier Error: TOC entry range arithmetic overflow"
        ),
        (
            IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS,
            0x000b0041,
            "Image Verifier Error: Digest out of bounds"
        ),
        (
            IMAGE_VERIFIER_ERR_ECC_KEY_DESCRIPTOR_VERSION_MISMATCH,
            0x000b0042,
            "Image Verifier Error: ECC key descriptor version mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_ECC_KEY_DESCRIPTOR_HASH_COUNT_GT_MAX,
            0x000b0043,
            "Image Verifier Error: ECC key descriptor hash count greater than max"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_DESCRIPTOR_VERSION_MISMATCH,
            0x000b0044,
            "Image Verifier Error: PQC key descriptor version mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_DESCRIPTOR_TYPE_MISMATCH,
            0x000b0045,
            "Image Verifier Error: PQC key descriptor type mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_DESCRIPTOR_HASH_COUNT_GT_MAX,
            0x000b0046,
            "Image Verifier Error: PQC key descriptor hash count greater than max"
        ),
        (
            IMAGE_VERIFIER_ERR_ECC_KEY_DESCRIPTOR_INVALID_HASH_COUNT,
            0x000b0047,
            "Image Verifier Error: ECC key descriptor invalid hash count"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_DESCRIPTOR_INVALID_HASH_COUNT,
            0x000b0048,
            "Image Verifier Error: PQC key descriptor invalid hash count"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_TYPE_INVALID,
            0x000b0049,
            "Image Verifier Error: PQC key type invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_LMS_VENDOR_PUB_KEY_INVALID,
            0x000b004a,
            "Image Verifier Error: LMS vendor public key invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_LMS_VENDOR_SIG_INVALID,
            0x000b004b,
            "Image Verifier Error: LMS vendor signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_LMS_OWNER_PUB_KEY_INVALID,
            0x000b004c,
            "Image Verifier Error: LMS owner public key invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_LMS_OWNER_SIG_INVALID,
            0x000b004d,
            "Image Verifier Error: LMS owner signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_MLDSA_VENDOR_PUB_KEY_READ_FAILED,
            0x000b004e,
            "Image Verifier Error: MLDSA vendor public key read failed"
        ),
        (
            IMAGE_VERIFIER_ERR_MLDSA_VENDOR_SIG_READ_FAILED,
            0x000b004f,
            "Image Verifier Error: MLDSA vendor signature read failed"
        ),
        (
            IMAGE_VERIFIER_ERR_MLDSA_OWNER_PUB_KEY_READ_FAILED,
            0x000b0050,
            "Image Verifier Error: MLDSA owner public key read failed"
        ),
        (
            IMAGE_VERIFIER_ERR_MLDSA_OWNER_SIG_READ_FAILED,
            0x000b0051,
            "Image Verifier Error: MLDSA owner signature read failed"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_MLDSA_MSG_MISSING,
            0x000b0052,
            "Image Verifier Error: Vendor MLDSA message missing"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_MLDSA_MSG_MISSING,
            0x000b0053,
            "Image Verifier Error: Owner MLDSA message missing"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_MLDSA_VERIFY_FAILURE,
            0x000b0054,
            "Image Verifier Error: Vendor MLDSA verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_MLDSA_SIGNATURE_INVALID,
            0x000b0055,
            "Image Verifier Error: Vendor MLDSA signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_MLDSA_VERIFY_FAILURE,
            0x000b0056,
            "Image Verifier Error: Owner MLDSA verify failure"
        ),
        (
            IMAGE_VERIFIER_ERR_OWNER_MLDSA_SIGNATURE_INVALID,
            0x000b0057,
            "Image Verifier Error: Owner MLDSA signature invalid"
        ),
        (
            IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED,
            0x000b0058,
            "Image Verifier Error: MLDSA type conversion failed"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_DIGEST_MISMATCH,
            0x000b0059,
            "Image Verifier Error: Vendor ECC public key digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_VENDOR_PQC_PUB_KEY_DIGEST_MISMATCH,
            0x000b005a,
            "Image Verifier Error: Vendor PQC public key digest mismatch"
        ),
        (
            IMAGE_VERIFIER_ERR_INVALID_PQC_KEY_TYPE_IN_FUSE,
            0x000b005b,
            "Image Verifier Error: Invalid PQC key type in fuse"
        ),
        (
            IMAGE_VERIFIER_ERR_PQC_KEY_TYPE_MISMATCH,
            0x000b005c,
            "Image Verifier Error: PQC key type mismatch"
        ),
        (
            IMAGE_VERIFIER_ACTIVATION_FAILED,
            0x000b005d,
            "Image Verifier Error: Activation failed"
        ),
        (
            IMAGE_VERIFIER_ERR_DOT_OWNER_PUB_KEY_DIGEST_MISMATCH,
            0x000b005e,
            "Image Verifier Error: DOT owner public key digest mismatch"
        ),
        (
            DRIVER_LMS_INVALID_LMS_ALGO_TYPE,
            0x000c0001,
            "Driver Error: LMS invalid LMS algorithm type"
        ),
        (
            DRIVER_LMS_INVALID_LMOTS_ALGO_TYPE,
            0x000c0002,
            "Driver Error: LMS invalid LMOTS algorithm type"
        ),
        (
            DRIVER_LMS_INVALID_WINTERNITS_PARAM,
            0x000c0003,
            "Driver Error: LMS invalid Winternitz parameter"
        ),
        (
            DRIVER_LMS_INVALID_PVALUE,
            0x000c0004,
            "Driver Error: LMS invalid p-value"
        ),
        (
            DRIVER_LMS_INVALID_HASH_WIDTH,
            0x000c0005,
            "Driver Error: LMS invalid hash width"
        ),
        (
            DRIVER_LMS_INVALID_TREE_HEIGHT,
            0x000c0006,
            "Driver Error: LMS invalid tree height"
        ),
        (
            DRIVER_LMS_INVALID_Q_VALUE,
            0x000c0007,
            "Driver Error: LMS invalid q-value"
        ),
        (
            DRIVER_LMS_INVALID_INDEX,
            0x000c0008,
            "Driver Error: LMS invalid index"
        ),
        (
            DRIVER_LMS_PATH_OUT_OF_BOUNDS,
            0x000c0009,
            "Driver Error: LMS path out of bounds"
        ),
        (
            DRIVER_LMS_INVALID_SIGNATURE_LENGTH,
            0x000c000a,
            "Driver Error: LMS invalid signature length"
        ),
        (
            DRIVER_LMS_INVALID_PUBLIC_KEY_LENGTH,
            0x000c000b,
            "Driver Error: LMS invalid public key length"
        ),
        (
            DRIVER_LMS_INVALID_SIGNATURE_DEPTH,
            0x000c000c,
            "Driver Error: LMS invalid signature depth"
        ),
        (
            DRIVER_LMS_SIGNATURE_LMOTS_DOESNT_MATCH_PUBKEY_LMOTS,
            0x000c000d,
            "Driver Error: LMS signature LMOTS doesn't match pubkey LMOTS"
        ),
        (
            DRIVER_CSRNG_INSTANTIATE,
            0x000d0001,
            "CSRNG Error: Instantiate"
        ),
        (
            DRIVER_CSRNG_UNINSTANTIATE,
            0x000d0002,
            "CSRNG Error: Uninstantiate"
        ),
        (DRIVER_CSRNG_RESEED, 0x000d0003, "CSRNG Error: Reseed"),
        (DRIVER_CSRNG_GENERATE, 0x000d0004, "CSRNG Error: Generate"),
        (DRIVER_CSRNG_UPDATE, 0x000d0005, "CSRNG Error: Update"),
        (
            DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED,
            0x000d0006,
            "CSRNG Error: Other health check failed"
        ),
        (
            DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED,
            0x000d0007,
            "CSRNG Error: RepCnt health check failed"
        ),
        (
            DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED,
            0x000d0008,
            "CSRNG Error: AdaptP health check failed"
        ),
        (
            DRIVER_HANDOFF_INVALID_VAULT,
            0x000D100,
            "Driver Handoff Error: Invalid vault"
        ),
        (
            DRIVER_HANDOFF_INVALID_KEY_ID,
            0x000D101,
            "Driver Handoff Error: Invalid key ID"
        ),
        (
            DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY4,
            0x000D102,
            "Driver Handoff Error: Invalid cold reset entry4"
        ),
        (
            DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY48,
            0x000D103,
            "Driver Handoff Error: Invalid cold reset entry48"
        ),
        (
            DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY4,
            0x000D104,
            "Driver Handoff Error: Invalid warm reset entry4"
        ),
        (
            DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY48,
            0x000D105,
            "Driver Handoff Error: Invalid warm reset entry48"
        ),
        (
            DRIVER_DMA_TRANSACTION_ALREADY_BUSY,
            0x0000f000,
            "DMA driver Error: Transaction already busy"
        ),
        (
            DRIVER_DMA_TRANSACTION_ERROR,
            0x0000f001,
            "DMA driver Error: Transaction error"
        ),
        (
            DRIVER_DMA_FIFO_UNDERRUN,
            0x0000f002,
            "DMA driver Error: FIFO underrun"
        ),
        (
            DRIVER_DMA_FIFO_OVERRUN,
            0x0000f003,
            "DMA driver Error: FIFO overrun"
        ),
        (
            DRIVER_DMA_FIFO_INVALID_SIZE,
            0x0000f004,
            "DMA driver Error: FIFO invalid size"
        ),
        (
            DRIVER_DMA_SHA_ACCELERATOR_NOT_LOCKED,
            0x0000f005,
            "DMA driver Error: SHA accelerator not locked by DMA"
        ),
        (
            DRIVER_DMA_INVALID_DMA_TARGET,
            0x0000f006,
            "DMA driver Error: Invalid target"
        ),
        (
            DRIVER_SHA3_INVALID_STATE_ERR,
            0x0001f000,
            "SHA3 driver Error: Invalid op state"
        ),
        (
            DRIVER_SHA3_DIGEST_EXCEEDS_RATE,
            0x0001f001,
            "SHA3 driver Error: Requested digest greater than mode/strength rate"
        ),
        (RUNTIME_INTERNAL, 0x000E0001, "Runtime Error: Internal"),
        (
            RUNTIME_UNIMPLEMENTED_COMMAND,
            0x000E0002,
            "Runtime Error: Unimplemented command"
        ),
        (
            RUNTIME_INSUFFICIENT_MEMORY,
            0x000E0003,
            "Runtime Error: Insufficient memory"
        ),
        (
            RUNTIME_ECDSA_VERIFY_FAILED,
            0x000E0004,
            "Runtime Error: ECDSA verify failed"
        ),
        (
            RUNTIME_INVALID_CHECKSUM,
            0x000E0005,
            "Runtime Error: Invalid checksum"
        ),
        (
            RUNTIME_HANDOFF_FHT_NOT_LOADED,
            0x000E0006,
            "Runtime Error: Handoff FHT not loaded"
        ),
        (
            RUNTIME_UNEXPECTED_UPDATE_RETURN,
            0x000E0007,
            "Runtime Error: Unexpected update return"
        ),
        (RUNTIME_SHUTDOWN, 0x000E0008, "Runtime Error: Shutdown"),
        (
            RUNTIME_MAILBOX_INVALID_PARAMS,
            0x000E0009,
            "Runtime Error: Mailbox invalid params"
        ),
        (RUNTIME_GLOBAL_NMI, 0x000E000A, "Runtime Error: Global NMI"),
        (
            RUNTIME_GLOBAL_EXCEPTION,
            0x000E000B,
            "Runtime Error: Global exception"
        ),
        (
            RUNTIME_GLOBAL_PANIC,
            0x000E000C,
            "Runtime Error: Global panic"
        ),
        (
            RUNTIME_HMAC_VERIFY_FAILED,
            0x000E000D,
            "Runtime Error: HMAC verify failed"
        ),
        (
            RUNTIME_INITIALIZE_DPE_FAILED,
            0x000E000E,
            "Runtime Error: Initialize DPE failed"
        ),
        (
            RUNTIME_GET_IDEVID_CERT_FAILED,
            0x000E000F,
            "Runtime Error: Get IDevID cert failed"
        ),
        (
            RUNTIME_CERT_CHAIN_CREATION_FAILED,
            0x000E0010,
            "Runtime Error: Cert chain creation failed"
        ),
        (
            RUNTIME_SELF_TEST_IN_PROGRESS,
            0x000E0011,
            "Runtime Error: Self test in progress"
        ),
        (
            RUNTIME_SELF_TEST_NOT_STARTED,
            0x000E0012,
            "Runtime Error: Self test not started"
        ),
        (
            RUNTIME_INVALID_FMC_SIZE,
            0x000E0013,
            "Runtime Error: Invalid FMC size"
        ),
        (
            RUNTIME_INVALID_RUNTIME_SIZE,
            0x000E0014,
            "Runtime Error: Invalid runtime size"
        ),
        (
            RUNTIME_FMC_CERT_HANDOFF_FAILED,
            0x000E0015,
            "Runtime Error: FMC cert handoff failed"
        ),
        (
            RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL,
            0x000E0016,
            "Runtime Error: Incorrect pauser privilege level"
        ),
        (
            RUNTIME_DPE_VALIDATION_FAILED,
            0x000E0017,
            "Runtime Error: DPE validation failed"
        ),
        (
            RUNTIME_UNKNOWN_RESET_FLOW,
            0x000E0018,
            "Runtime Error: Unknown reset flow"
        ),
        (
            RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED,
            0x000E0019,
            "Runtime Error: PL0 used DPE context threshold exceeded"
        ),
        (
            RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_EXCEEDED,
            0x000E001A,
            "Runtime Error: PL1 used DPE context threshold exceeded"
        ),
        (
            RUNTIME_GLOBAL_WDT_EXPIRED,
            0x000E001B,
            "Runtime Error: Global WDT expired"
        ),
        (
            RUNTIME_IDEV_CERT_POPULATION_FAILED,
            0x000E001C,
            "Runtime Error: IDevID cert population failed"
        ),
        (
            RUNTIME_ADD_ROM_MEASUREMENTS_TO_DPE_FAILED,
            0x000E001D,
            "Runtime Error: Add ROM measurements to DPE failed"
        ),
        (
            RUNTIME_TAGGING_FAILURE,
            0x000E001E,
            "Runtime Error: Tagging failure"
        ),
        (
            RUNTIME_DUPLICATE_TAG,
            0x000E001F,
            "Runtime Error: Duplicate tag"
        ),
        (
            RUNTIME_CONTEXT_ALREADY_TAGGED,
            0x000E0020,
            "Runtime Error: Context already tagged"
        ),
        (
            RUNTIME_ADD_VALID_PAUSER_MEASUREMENT_TO_DPE_FAILED,
            0x000E0021,
            "Runtime Error: Add valid pauser measurement to DPE failed"
        ),
        (
            RUNTIME_MAILBOX_API_RESPONSE_DATA_LEN_TOO_LARGE,
            0x000E0022,
            "Runtime Error: Mailbox API response data length too large"
        ),
        (
            RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE,
            0x000E0023,
            "Runtime Error: Mailbox API request data length too large"
        ),
        (
            RUNTIME_LDEVID_CERT_HANDOFF_FAILED,
            0x000E0024,
            "Runtime Error: LDevID cert handoff failed"
        ),
        (
            RUNTIME_CONTEXT_TAGS_VALIDATION_FAILED,
            0x000E0025,
            "Runtime Error: Context tags validation failed"
        ),
        (
            RUNTIME_COULD_NOT_GET_DPE_PROFILE,
            0x000E0026,
            "Runtime Error: Could not get DPE profile"
        ),
        (
            RUNTIME_DPE_COMMAND_DESERIALIZATION_FAILED,
            0x000E0027,
            "Runtime Error: DPE command deserialization failed"
        ),
        (
            GET_LDEVID_CERT_FAILED,
            0x000E0028,
            "Caliptra Error: Get LDevID cert failed"
        ),
        (
            RUNTIME_GET_FMC_ALIAS_CERT_FAILED,
            0x000E0029,
            "Runtime Error: Get FMC alias cert failed"
        ),
        (
            RUNTIME_GET_RT_ALIAS_CERT_FAILED,
            0x000E002A,
            "Runtime Error: Get RT alias cert failed"
        ),
        (
            RUNTIME_CMD_BUSY_DURING_WARM_RESET,
            0x000E002B,
            "Runtime Error: Command busy during warm reset"
        ),
        (
            RUNTIME_FW_SVN_HANDOFF_FAILED,
            0x000E002C,
            "Runtime Error: FW SVN handoff failed"
        ),
        (
            RUNTIME_FW_MIN_SVN_HANDOFF_FAILED,
            0x000E002D,
            "Runtime Error: FW min SVN handoff failed"
        ),
        (
            RUNTIME_COLD_BOOT_FW_SVN_HANDOFF_FAILED,
            0x000E002E,
            "Runtime Error: Cold boot FW SVN handoff failed"
        ),
        (
            RUNTIME_CONTEXT_HAS_TAG_VALIDATION_FAILED,
            0x000E002F,
            "Runtime Error: Context has tag validation failed"
        ),
        (
            RUNTIME_LDEV_ID_CERT_TOO_BIG,
            0x000E0030,
            "Runtime Error: LDevID cert too big"
        ),
        (
            RUNTIME_FMC_ALIAS_CERT_TOO_BIG,
            0x000E0031,
            "Runtime Error: FMC alias cert too big"
        ),
        (
            RUNTIME_RT_ALIAS_CERT_TOO_BIG,
            0x000E0032,
            "Runtime Error: RT alias cert too big"
        ),
        (
            RUNTIME_COMPUTE_RT_ALIAS_SN_FAILED,
            0x000E0033,
            "Runtime Error: Compute RT alias SN failed"
        ),
        (
            RUNTIME_RT_JOURNEY_PCR_VALIDATION_FAILED,
            0x000E0034,
            "Runtime Error: RT journey PCR validation failed"
        ),
        (
            RUNTIME_UNABLE_TO_FIND_DPE_ROOT_CONTEXT,
            0x000E0035,
            "Runtime Error: Unable to find DPE root context"
        ),
        (
            RUNTIME_INCREMENT_PCR_RESET_MAX_REACHED,
            0x000E0036,
            "Runtime Error: Increment PCR reset max reached"
        ),
        (
            RUNTIME_PL0_USED_DPE_CONTEXT_THRESHOLD_REACHED,
            0x000E0037,
            "Runtime Error: PL0 used DPE context threshold reached"
        ),
        (
            RUNTIME_PL1_USED_DPE_CONTEXT_THRESHOLD_REACHED,
            0x000E0038,
            "Runtime Error: PL1 used DPE context threshold reached"
        ),
        (
            RUNTIME_CDI_KV_HDL_HANDOFF_FAILED,
            0x000E0039,
            "Runtime Error: CDI KV HDL handoff failed"
        ),
        (
            RUNTIME_PRIV_KEY_KV_HDL_HANDOFF_FAILED,
            0x000E003A,
            "Runtime Error: Private key KV HDL handoff failed"
        ),
        (
            RUNTIME_KEY_LADDER_HANDOFF_FAILED,
            0x000E003B,
            "Runtime Error: Key ladder handoff failed"
        ),
        (
            RUNTIME_PCR_RESERVED,
            0x000E003C,
            "PCR Runtime Error: Reserved"
        ),
        (
            RUNTIME_PCR_INVALID_INDEX,
            0x000E003D,
            "PCR Runtime Error: Invalid index"
        ),
        (
            RUNTIME_DMTF_DEVICE_INFO_VALIDATION_FAILED,
            0x000E003E,
            "Runtime Error: DMTF device info validation failed"
        ),
        (
            RUNTIME_STORE_DMTF_DEVICE_INFO_FAILED,
            0x000E003F,
            "Runtime Error: Store DMTF device info failed"
        ),
        (
            RUNTIME_CERTIFY_KEY_EXTENDED_FAILED,
            0x000E0040,
            "Runtime Error: Certify key extended failed"
        ),
        (
            RUNTIME_DPE_RESPONSE_SERIALIZATION_FAILED,
            0x000E0041,
            "Runtime Error: DPE response serialization failed"
        ),
        (
            RUNTIME_LMS_VERIFY_FAILED,
            0x000E0042,
            "Runtime Error: LMS verify failed"
        ),
        (
            RUNTIME_LMS_VERIFY_INVALID_LMS_ALGORITHM,
            0x000E0043,
            "Runtime Error: LMS verify invalid LMS algorithm"
        ),
        (
            RUNTIME_LMS_VERIFY_INVALID_LMOTS_ALGORITHM,
            0x000E0044,
            "Runtime Error: LMS verify invalid LMOTS algorithm"
        ),
        (
            RUNTIME_INVALID_AUTH_MANIFEST_MARKER,
            0x000E0045,
            "Runtime Error: Invalid auth manifest marker"
        ),
        (
            RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH,
            0x000E0046,
            "Runtime Error: Auth manifest preamble size mismatch"
        ),
        (
            RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
            0x000E0047,
            "Runtime Error: Auth manifest vendor ECC signature invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
            0x000E0048,
            "Runtime Error: Auth manifest vendor LMS signature invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
            0x000E0049,
            "Runtime Error: Auth manifest owner ECC signature invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            0x000E004A,
            "Runtime Error: Auth manifest owner LMS signature invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN,
            0x000E004B,
            "Runtime Error: Auth manifest preamble size less than min"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE,
            0x000E004C,
            "Runtime Error: Auth manifest image metadata list invalid size"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
            0x000E004D,
            "Runtime Error: Auth manifest image metadata list invalid entry count"
        ),
        (
            RUNTIME_AUTH_AND_STASH_UNSUPPORTED_IMAGE_SOURCE,
            0x000E004E,
            "Runtime Error: Auth and stash unsupported image source"
        ),
        (
            RUNTIME_CMD_RESERVED_PAUSER,
            0x000E004F,
            "Runtime Error: Command reserved pauser"
        ),
        (
            RUNTIME_AUTH_AND_STASH_MEASUREMENT_DPE_ERROR,
            0x000E0050,
            "Runtime Error: Auth and stash measurement DPE error"
        ),
        (
            RUNTIME_GET_IDEV_ID_UNPROVISIONED,
            0x000E0051,
            "Runtime Error: Get IDevID unprovisioned"
        ),
        (
            RUNTIME_GET_IDEV_ID_UNSUPPORTED_ROM,
            0x000E0052,
            "Runtime Error: Get IDevID unsupported ROM"
        ),
        (
            RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_DUPLICATE_FIRMWARE_ID,
            0x000E0053,
            "Runtime Error: Auth manifest image metadata list duplicate firmware ID"
        ),
        (
            RUNTIME_AUTH_MANIFEST_LMS_VENDOR_PUB_KEY_INVALID,
            0x000E0054,
            "Runtime Error: Auth manifest LMS vendor public key invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_LMS_OWNER_PUB_KEY_INVALID,
            0x000E0055,
            "Runtime Error: Auth manifest LMS owner public key invalid"
        ),
        (
            RUNTIME_KEY_LADDER_TARGET_SVN_TOO_LARGE,
            0x000E0056,
            "Runtime Error: Key ladder target SVN too large"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
            0x000E0057,
            "Runtime Error: Sign with exported ECDSA key derivation failed"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_SIGNATURE_FAILED,
            0x000E0058,
            "Runtime Error: Sign with exported ECDSA signature failed"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_DIGEST,
            0x000E0059,
            "Runtime Error: Sign with exported ECDSA invalid digest"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_ECDSA_INVALID_SIGNATURE,
            0x000E005A,
            "Runtime Error: Sign with exported ECDSA invalid signature"
        ),
        (
            RUNTIME_GET_FMC_CSR_UNPROVISIONED,
            0x000E005B,
            "Runtime Error: Get FMC CSR unprovisioned"
        ),
        (
            RUNTIME_GET_FMC_CSR_UNSUPPORTED_FMC,
            0x000E005C,
            "Runtime Error: Get FMC CSR unsupported FMC"
        ),
        (
            RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE,
            0x000E005D,
            "Runtime Error: Invalid combination of key usage and size"
        ),
        (
            RUNTIME_CMB_KEY_USAGE_STORAGE_FULL,
            0x000E005E,
            "Runtime Error: Key usage storage full"
        ),
        (
            RUNTIME_CMB_NOT_INITIALIZED,
            0x000E005F,
            "Runtime Error: Crypto mailbox system not initialized"
        ),
        (
            RUNTIME_REVOKE_EXPORTED_CDI_HANDLE_NOT_FOUND,
            0x000E0060,
            "Runtime Error: CDI Handle not found"
        ),
        (
            RUNTIME_IMAGE_METADATA_NOT_FOUND,
            0x000E0061,
            "Runtime Error: Image metadata not found"
        ),
        (
            RUNTIME_SIGN_WITH_EXPORTED_MLDSA_NOT_SUPPORTED,
            0x000E0062,
            "Runtime Error: Sign with exported MLDSA not supported"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_PUB_KEY_READ_FAILED,
            0x000E0063,
            "Runtime Error: Auth manifest MLDSA vendor public key read failed"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_READ_FAILED,
            0x000E0064,
            "Runtime Error: Auth manifest MLDSA vendor signature read failed"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_INVALID,
            0x000E0065,
            "Runtime Error: Auth manifest MLDSA vendor signature invalid"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_PUB_KEY_READ_FAILED,
            0x000E0066,
            "Runtime Error: Auth manifest MLDSA owner public key read failed"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_READ_FAILED,
            0x000E0067,
            "Runtime Error: Auth manifest MLDSA owner signature read failed"
        ),
        (
            RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_INVALID,
            0x000E0068,
            "Runtime Error: Auth manifest MLDSA owner signature invalid"
        ),
        (
            RUNTIME_DEBUG_UNLOCK_INVALID_LIFECYCLE,
            0x000E0069,
            "Runtime Error: Debug unlock invalid lifecycle"
        ),
        (
            RUNTIME_DEBUG_UNLOCK_NO_CHALLENGE,
            0x000E006A,
            "Runtime Error: Debug unlock no challenge available"
        ),
        (
            RUNTIME_DEBUG_UNLOCK_NO_REQUEST,
            0x000E006B,
            "Runtime Error: Debug unlock no request available"
        ),
        (
            RUNTIME_MLDSA_VERIFY_FAILED,
            0x000E006C,
            "Runtime Error: MLDSA verify failed"
        ),
        (
            RUNTIME_GCM_KEY_USAGE_LIMIT_REACHED,
            0x000E006D,
            "Runtime Error: AES GCM key usage limit reached"
        ),
        (
            RUNTIME_FE_PROG_ILLEGAL_LIFECYCLE_STATE,
            0x000E006E,
            "Runtime Error: FE programming illegal lifecycle state"
        ),
        (
            RUNTIME_FE_PROG_INVALID_PARTITION,
            0x000E006F,
            "Runtime Error: FE programming invalid partition number"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_MIN,
            0x000E0070,
            "Runtime Error: Reallocate DPE context requested less than the minimum PL0 contexts"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_GREATER_THAN_MAX,
            0x000E0071,
            "Runtime Error: Reallocate DPE context requested greater than the maximum PL0 contexts"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL0_LESS_THAN_USED,
            0x000E0072,
            "Runtime Error: Reallocate DPE context requested fewer PL0 contexts than are used currently"
        ),
        (
            RUNTIME_REALLOCATE_DPE_CONTEXTS_PL1_LESS_THAN_USED,
            0x000E0073,
            "Runtime Error: Reallocate DPE context requested fewer PL1 contexts than are used currently"
        ),
        // TODO(clundin): Align error codes with OCP LOCK spec.
        (
            RUNTIME_OCP_LOCK_UNSUPPORTED_COMMAND,
            0x000E0074,
            "OCP LOCK Error: Unsupported command"
        ),
        (
            RUNTIME_OCP_LOCK_HEK_UNAVAILABLE,
            0x000E0075,
            "OCP LOCK Error: HEK Unavailable to runtime"
        ),
        (
            RUNTIME_OCP_LOCK_MEK_NOT_INITIALIZED,
            0x000E0076,
            "OCP LOCK Error: MEK was not initialized by OCP_LOCK_INITIALIZE_MEK_SECRET"
        ),
        (
            RUNTIME_OCP_LOCK_INVALID_MEK_SECRET_SEED_SIZE,
            0x000E0077,
            "OCP LOCK Error: Invalid MEK secret seed size"
        ),
        (
            RUNTIME_OCP_LOCK_INVALID_MEK_SEED_SIZE,
            0x000E0078,
            "OCP LOCK Error: Invalid MEK seed size"
        ),
        (
            RUNTIME_OCP_LOCK_MEK_CHKSUM_FAIL,
            0x000E0079,
            "OCP LOCK Error: Error in derivation caused MEK mismatch"
        ),
        (
            RUNTIME_OCP_LOCK_UNKNOWN_HPKE_HANDLE,
            0x000E007F,
            "OCP LOCK Error: received an unknown hpke handle"
        ),
        (
            RUNTIME_OCP_LOCK_FAILED_TO_CONVERT_WRAPPED_KEY,
            0x000E0080,
            "OCP LOCK Error: failed to convert wrapped key"
        ),
        (
            RUNTIME_OCP_LOCK_FAILED_TO_GENERATE_MEK,
            0x000E0081,
            "OCP LOCK Error: failed to generate MEK"
        ),
        (
            RUNTIME_OCP_LOCK_UNKNOWN_ENDORSEMENT_ALGORITHM,
            0x000E0082,
            "OCP LOCK Error: received an unknown endorsement algorithm"
        ),
        (
            RUNTIME_OCP_LOCK_UNKNOWN_KEM_ALGORITHM,
            0x000E0083,
            "OCP LOCK Error: received an unknown KEM algorithm"
        ),
        (
            RUNTIME_OCP_LOCK_ENDORSEMENT_CERT_ENCODING_ERROR,
            0x000E0084,
            "OCP LOCK Error: endorsement certificate encoding error"
        ),
        (
            RUNTIME_INVALID_ROM_PERSISTENT_DATA_MARKER,
            0x000E007A,
            "Runtime Error: Invalid ROM persistent data marker"
        ),
        (
            RUNTIME_INVALID_ROM_PERSISTENT_DATA_VERSION,
            0x000E007B,
            "Runtime Error: Invalid ROM persistent data version"
        ),
        (
            RUNTIME_INVALID_FW_PERSISTENT_DATA_MARKER,
            0x000E007C,
            "Runtime Error: Invalid FW persistent data marker"
        ),
        (
            RUNTIME_INVALID_FW_PERSISTENT_DATA_VERSION,
            0x000E007D,
            "Runtime Error: Invalid FW persistent data version"
        ),
        (
            RUNTIME_RT_CURRENT_PCR_VALIDATION_FAILED,
            0x000E007E,
            "Runtime Error: RT current PCR validation failed"
        ),
        (
            RUNTIME_CMB_DMA_SHA384_MISMATCH,
            0x000E0085,
            "Runtime Error: DMA SHA384 hash mismatch during encrypted firmware decryption"
        ),
        // FMC Errors
        (FMC_GLOBAL_NMI, 0x000F0001, "FMC Error: Global NMI"),
        (
            FMC_GLOBAL_EXCEPTION,
            0x000F0002,
            "FMC Error: Global exception"
        ),
        (FMC_GLOBAL_PANIC, 0x000F0003, "FMC Error: Global panic"),
        (
            FMC_HANDOFF_INVALID_PARAM,
            0x000F0004,
            "FMC Error: Handoff invalid param"
        ),
        (
            FMC_RT_ALIAS_DERIVE_FAILURE,
            0x000F0005,
            "FMC Error: RT alias derive failure"
        ),
        (
            FMC_RT_ALIAS_CERT_VERIFY,
            0x000F0006,
            "FMC Error: RT alias cert verify"
        ),
        (
            FMC_RT_ALIAS_ECC_TBS_SIZE_EXCEEDED,
            0x000F0007,
            "FMC Error: RT alias ECC TBS size exceeded"
        ),
        (
            FMC_CDI_KV_COLLISION,
            0x000F0008,
            "FMC Error: CDI KV collision"
        ),
        (
            FMC_ALIAS_KV_COLLISION,
            0x000F0009,
            "FMC Error: Alias KV collision"
        ),
        (
            FMC_GLOBAL_PCR_LOG_EXHAUSTED,
            0x000F000A,
            "FMC Error: Global PCR log exhausted"
        ),
        (
            ADDRESS_NOT_IN_ICCM,
            0x000F000B,
            "FMC Error: Address not in ICCM"
        ),
        (
            FMC_HANDOFF_NOT_READY_FOR_RT,
            0x000F000C,
            "FMC Error: Handoff not ready for RT"
        ),
        (
            FMC_GLOBAL_WDT_EXPIRED,
            0x000F000D,
            "FMC Error: Global WDT expired"
        ),
        (FMC_UNKNOWN_RESET, 0x000F000E, "FMC Error: Unknown reset"),
        (
            FMC_ALIAS_CSR_BUILDER_INIT_FAILURE,
            0x000F000F,
            "FMC Alias CSR Error: Builder init failure"
        ),
        (
            FMC_ALIAS_CSR_BUILDER_BUILD_FAILURE,
            0x000F0010,
            "FMC Alias CSR Error: Builder build failure"
        ),
        (
            FMC_ALIAS_INVALID_CSR,
            0x000F0011,
            "FMC Alias CSR Error: Invalid CSR"
        ),
        (
            FMC_ALIAS_CSR_VERIFICATION_FAILURE,
            0x000F0012,
            "FMC Alias CSR Error: Verification failure"
        ),
        (
            FMC_ALIAS_CSR_OVERFLOW,
            0x000F0013,
            "FMC Alias CSR Error: Overflow"
        ),
        (
            FMC_RT_ALIAS_MLDSA_TBS_SIZE_EXCEEDED,
            0x000F00014,
            "FMC Error: RT alias MLDSA TBS size exceeded"
        ),
        (
            FMC_INVALID_ROM_PERSISTENT_DATA_MARKER,
            0x000F00015,
            "FMC Error: Invalid ROM persistent data marker"
        ),
        (
            FMC_INVALID_ROM_PERSISTENT_DATA_VERSION,
            0x000F00016,
            "FMC Error: Invalid ROM persistent data version"
        ),
        (
            FMC_INVALID_FW_PERSISTENT_DATA_MARKER,
            0x000F00017,
            "FMC Error: Invalid FW persistent data marker"
        ),
        (
            FMC_INVALID_FW_PERSISTENT_DATA_VERSION,
            0x000F00018,
            "FMC Error: Invalid FW persistent data version"
        ),
        (
            DRIVER_TRNG_EXT_TIMEOUT,
            0x00100001,
            "TRNG_EXT Error: Timeout"
        ),
        (
            DRIVER_SOC_IFC_INVALID_TIMER_CONFIG,
            0x00100002,
            "SOC_IFC driver Error: Invalid timer config"
        ),
        (
            DRIVER_TRNG_UPDATE_NOT_SUPPORTED,
            0x00100003,
            "TRNG_EXT Error: Update not supported"
        ),
        (
            ADDRESS_MISALIGNED,
            0x00110000,
            "Bounded address Error: Misaligned"
        ),
        (
            ADDRESS_NOT_IN_ROM,
            0x00110001,
            "Bounded address Error: Not in ROM"
        ),
        (
            ROM_IDEVID_CSR_BUILDER_INIT_FAILURE,
            0x01000001,
            "Initial Device ID Error: CSR builder init failure"
        ),
        (
            ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE,
            0x01000002,
            "Initial Device ID Error: CSR builder build failure"
        ),
        (
            ROM_IDEVID_INVALID_CSR,
            0x01000003,
            "Initial Device ID Error: Invalid CSR"
        ),
        (
            ROM_IDEVID_CSR_VERIFICATION_FAILURE,
            0x01000004,
            "Initial Device ID Error: CSR verification failure"
        ),
        (
            ROM_IDEVID_CSR_OVERFLOW,
            0x01000005,
            "Initial Device ID Error: CSR overflow"
        ),
        (
            ROM_LDEVID_CSR_VERIFICATION_FAILURE,
            0x01010001,
            "ROM Local Device ID Error: CSR verification failure"
        ),
        (
            FW_PROC_MANIFEST_READ_FAILURE,
            0x01020001,
            "Firmware Processor Error: Manifest read failure"
        ),
        (
            FW_PROC_INVALID_IMAGE_SIZE,
            0x01020002,
            "Firmware Processor Error: Invalid image size"
        ),
        (
            FW_PROC_MAILBOX_STATE_INCONSISTENT,
            0x01020003,
            "Firmware Processor Error: Mailbox state inconsistent"
        ),
        (
            FW_PROC_MAILBOX_INVALID_COMMAND,
            0x01020004,
            "Firmware Processor Error: Mailbox invalid command"
        ),
        (
            FW_PROC_MAILBOX_INVALID_CHECKSUM,
            0x01020005,
            "Firmware Processor Error: Mailbox invalid checksum"
        ),
        (
            FW_PROC_MAILBOX_INVALID_REQUEST_LENGTH,
            0x01020006,
            "Firmware Processor Error: Mailbox invalid request length"
        ),
        (
            FW_PROC_MAILBOX_PROCESS_FAILURE,
            0x01020007,
            "Firmware Processor Error: Mailbox process failure"
        ),
        (
            FW_PROC_MAILBOX_STASH_MEASUREMENT_MAX_LIMIT,
            0x01020008,
            "Firmware Processor Error: Mailbox stash measurement max limit"
        ),
        (
            FW_PROC_MAILBOX_RESERVED_PAUSER,
            0x01020009,
            "Firmware Processor Error: Mailbox reserved pauser"
        ),
        (
            FW_PROC_MAILBOX_GET_IDEV_CSR_UNPROVISIONED_CSR,
            0x0102000A,
            "Firmware Processor Error: Mailbox get IDevID CSR unprovisioned CSR"
        ),
        (
            FW_PROC_MAILBOX_FW_LOAD_CMD_IN_SUBSYSTEM_MODE,
            0x0102000B,
            "Firmware Processor Error: Mailbox FW load command in active mode"
        ),
        (
            FW_PROC_SVN_TOO_LARGE,
            0x0102000C,
            "Firmware Processor Error: SVN too large"
        ),
        (
            FW_PROC_OCP_LOCK_UNSUPPORTED,
            0x0102000D,
            "Firmware Processor Error: OCP LOCK is not supported"
        ),
        (
            FMC_ALIAS_CERT_VERIFY_FAILURE,
            0x01030001,
            "FMC Alias Layer Error: Certificate verification failure"
        ),
        (
            ROM_ECDSA_VERIFY_FAILED,
            0x01030002,
            "ROM Error: ECDSA verify failed"
        ),
        (
            ROM_MLDSA_VERIFY_FAILED,
            0x01030003,
            "ROM Error: MLDSA verify failed"
        ),
        (
            ROM_UPDATE_RESET_FLOW_MANIFEST_READ_FAILURE,
            0x01040002,
            "Update Reset Error: Flow manifest read failure"
        ),
        (
            ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND,
            0x01040003,
            "Update Reset Error: Flow invalid firmware command"
        ),
        (
            ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE,
            0x01040004,
            "Update Reset Error: Flow mailbox access failure"
        ),
        (
            ROM_UPDATE_RESET_READ_FHT_FAILURE,
            0x01040005,
            "Update Reset Error: Read FHT failure"
        ),
        (
            ROM_UPDATE_RESET_FLOW_IMAGE_NOT_IN_MCU_SRAM,
            0x01040006,
            "Update Reset Error: Image not in MCU SRAM"
        ),
        (
            ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET,
            0x01040010,
            "Warm Reset Error: Unsuccessful previous cold reset"
        ),
        (
            ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_UPDATE_RESET,
            0x01040011,
            "Warm Reset Error: Unsuccessful previous update reset"
        ),
        (
            ROM_UNKNOWN_RESET_FLOW,
            0x01040020,
            "Unknown Reset Error: Flow"
        ),
        (
            ROM_CFI_PANIC_UNKNOWN,
            0x01040050,
            "ROM CFI Error: Panic unknown"
        ),
        (
            ROM_CFI_PANIC_COUNTER_CORRUPT,
            0x01040051,
            "ROM CFI Error: Panic counter corrupt"
        ),
        (
            ROM_CFI_PANIC_COUNTER_OVERFLOW,
            0x01040052,
            "ROM CFI Error: Panic counter overflow"
        ),
        (
            ROM_CFI_PANIC_COUNTER_UNDERFLOW,
            0x01040053,
            "ROM CFI Error: Panic counter underflow"
        ),
        (
            ROM_CFI_PANIC_COUNTER_MISMATCH,
            0x01040054,
            "ROM CFI Error: Panic counter mismatch"
        ),
        (
            ROM_CFI_PANIC_ASSERT_EQ_FAILURE,
            0x01040055,
            "ROM CFI Error: Panic assert eq failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_NE_FAILURE,
            0x01040056,
            "ROM CFI Error: Panic assert ne failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_GT_FAILURE,
            0x01040057,
            "ROM CFI Error: Panic assert gt failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_LT_FAILURE,
            0x01040058,
            "ROM CFI Error: Panic assert lt failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_GE_FAILURE,
            0x01040059,
            "ROM CFI Error: Panic assert ge failure"
        ),
        (
            ROM_CFI_PANIC_ASSERT_LE_FAILURE,
            0x0104005A,
            "ROM CFI Error: Panic assert le failure"
        ),
        (
            ROM_CFI_PANIC_TRNG_FAILURE,
            0x0104005B,
            "ROM CFI Error: Panic TRNG failure"
        ),
        (
            ROM_CFI_PANIC_UNEXPECTED_MATCH_BRANCH,
            0x0104005C,
            "ROM CFI Error: Panic unexpected match branch"
        ),
        (
            ROM_CFI_PANIC_FAKE_TRNG_USED_WITH_DEBUG_LOCK,
            0x0104005D,
            "ROM CFI Error: Panic fake TRNG used with debug lock"
        ),
        (
            ROM_UDS_PROG_ILLEGAL_LIFECYCLE_STATE,
            0x01045000,
            "ROM UDS Programming Error: Illegal lifecycle state"
        ),
        (
            ROM_UDS_PROG_IN_PASSIVE_MODE,
            0x01045001,
            "ROM UDS Programming Error: In passive mode"
        ),
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
            "ROM Global Error: PCR log invalid entry ID"
        ),
        (
            ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH,
            0x01050005,
            "ROM Global Error: PCR log unsupported data length"
        ),
        (
            ROM_GLOBAL_PCR_LOG_EXHAUSTED,
            0x01050006,
            "ROM Global Error: PCR log exhausted"
        ),
        (
            ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID,
            0x01050007,
            "ROM Global Error: Fuse log invalid entry ID"
        ),
        (
            ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH,
            0x01050008,
            "ROM Global Error: Fuse log unsupported data length"
        ),
        (
            ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE,
            0x01050009,
            "ROM Global Error: Unsupported LDevID TBS size"
        ),
        (
            ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE,
            0x0105000A,
            "ROM Global Error: Unsupported FMC alias TBS size"
        ),
        (
            ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION,
            0x0105000B,
            "ROM Global Error: Fake ROM in production"
        ),
        (
            ROM_GLOBAL_WDT_EXPIRED,
            0x0105000C,
            "ROM Global Error: WDT expired"
        ),
        (
            ROM_GLOBAL_MEASUREMENT_LOG_EXHAUSTED,
            0x0105000D,
            "ROM Global Error: Measurement log exhausted"
        ),
        (
            ROM_GLOBAL_FIPS_HOOKS_ROM_EXIT,
            0x0105000F,
            "ROM Global Error: FIPS hooks ROM exit"
        ),
        (
            ROM_GLOBAL_UNSUPPORTED_HW_VERSION,
            0x01050010,
            "ROM Global Error: Unsupported HW version"
        ),
        (
            ROM_INVALID_ROM_PERSISTENT_DATA_MARKER,
            0x01050011,
            "ROM Error: Invalid ROM persistent data marker"
        ),
        (
            ROM_INVALID_ROM_PERSISTENT_DATA_VERSION,
            0x01050012,
            "ROM Error: Invalid ROM persistent data version"
        ),
        (
            KAT_SHA256_DIGEST_FAILURE,
            0x90010001,
            "ROM KAT Error: SHA256 digest failure"
        ),
        (
            KAT_SHA256_DIGEST_MISMATCH,
            0x90010002,
            "ROM KAT Error: SHA256 digest mismatch"
        ),
        (
            KAT_SHA384_DIGEST_FAILURE,
            0x90020001,
            "ROM KAT Error: SHA384 digest failure"
        ),
        (
            KAT_SHA384_DIGEST_MISMATCH,
            0x90020002,
            "ROM KAT Error: SHA384 digest mismatch"
        ),
        (
            KAT_HMAC384_FAILURE,
            0x90030001,
            "ROM KAT Error: HMAC384 failure"
        ),
        (
            KAT_HMAC384_TAG_MISMATCH,
            0x90030002,
            "ROM KAT Error: HMAC384 tag mismatch"
        ),
        // 0x90040001 was KAT_ECC384_SIGNATURE_GENERATE_FAILURE
        // 0x90040002 was KAT_ECC384_SIGNATURE_VERIFY_FAILURE
        (
            KAT_ECC384_SIGNATURE_MISMATCH,
            0x90040003,
            "ROM KAT Error: ECC384 signature mismatch"
        ),
        (
            KAT_ECC384_KEY_PAIR_GENERATE_FAILURE,
            0x90040004,
            "ROM KAT Error: ECC384 key pair generate failure"
        ),
        (
            KAT_ECC384_KEY_PAIR_VERIFY_FAILURE,
            0x90040005,
            "ROM KAT Error: ECC384 key pair verify failure"
        ),
        (
            KAT_MLDSA87_SIGNATURE_MISMATCH,
            0x90040006,
            "ROM KAT Error: MLDSA87 signature mismatch"
        ),
        (
            KAT_MLDSA87_SIGNATURE_FAILURE,
            0x90040007,
            "ROM KAT Error: MLDSA87 signature failure"
        ),
        (
            KAT_MLDSA87_KEY_PAIR_GENERATE_FAILURE,
            0x90040008,
            "ROM KAT Error: MLDSA87 key pair generate failure"
        ),
        (
            KAT_MLDSA87_KEY_PAIR_VERIFY_FAILURE,
            0x90040009,
            "ROM KAT Error: MLDSA87 key pair verify failure"
        ),
        (
            KAT_ECDH_VERIFY_FAILURE,
            0x90040010,
            "ROM KAT Error: ECDH verify failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE,
            0x90050001,
            "ROM KAT Error: SHA2_512_384_ACC digest start op failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_FAILURE,
            0x90050002,
            "ROM KAT Error: SHA2_512_384_ACC digest failure"
        ),
        (
            KAT_SHA2_512_384_ACC_DIGEST_MISMATCH,
            0x90050003,
            "ROM KAT Error: SHA2_512_384_ACC digest mismatch"
        ),
        (
            KAT_SHA1_DIGEST_FAILURE,
            0x90060001,
            "ROM KAT Error: SHA1 digest failure"
        ),
        (
            KAT_SHA1_DIGEST_MISMATCH,
            0x90060002,
            "ROM KAT Error: SHA1 digest mismatch"
        ),
        (
            KAT_LMS_DIGEST_FAILURE,
            0x90070001,
            "ROM KAT Error: LMS digest failure"
        ),
        (
            KAT_LMS_DIGEST_MISMATCH,
            0x90070002,
            "ROM KAT Error: LMS digest mismatch"
        ),
        (
            KAT_AES_TAG_MISMATCH,
            0x90090001,
            "ROM KAT Error: AES tag mismatch"
        ),
        (
            KAT_AES_CIPHERTEXT_MISMATCH,
            0x90090002,
            "ROM KAT Error: AES ciphertext mismatch"
        ),
        (
            KAT_AES_PLAINTEXT_MISMATCH,
            0x90090003,
            "ROM KAT Error: AES plaintext mismatch"
        ),
        (
            KAT_CMAC_KDF_OUTPUT_MISMATCH,
            0x90090004,
            "ROM KAT Error: CMAC KDF output mismatch"
        ),
        (
            KAT_SHA512_DIGEST_FAILURE,
            0x90020003,
            "ROM KAT Error: SHA512 digest failure"
        ),
        (
            KAT_SHA512_DIGEST_MISMATCH,
            0x90020004,
            "ROM KAT Error: SHA512 digest mismatch"
        ),
        (
            KAT_SHA3_SHAKE256_DIGEST_FAILURE,
            0x900A0000,
            "ROM KAT Error: SHAKE256 digest failure"
        ),
        (
            KAT_SHA3_SHAKE256_DIGEST_MISMATCH,
            0x900A0001,
            "ROM KAT Error: SHAKE256 digest mismatch"
        ),
        (ROM_INTEGRITY_FAILURE, 0x90080001, "ROM integrity failure"),
        (
            FIPS_HOOKS_INJECTED_ERROR,
            0x90100000,
            "FIPS Hooks: Injected error"
        ),
        (
            SS_DBG_UNLOCK_INVALID_REQ_REG_VALUE,
            0xa0000000,
            "Debug unlock error: Invalid request register value"
        ),
        (
            SS_DBG_UNLOCK_MANUF_INVALID_MBOX_CMD,
            0xa0000001,
            "Debug unlock error: Manufacturing invalid mailbox command"
        ),
        (
            SS_DBG_UNLOCK_MANUF_INVALID_TOKEN,
            0xa0000002,
            "Debug unlock error: Manufacturing invalid token"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_REQ_MBOX_CMD,
            0xa0000003,
            "Debug unlock error: Production invalid request mailbox command"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_REQ,
            0xa0000004,
            "Debug unlock error: Production invalid request"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_LEVEL,
            0xa0000005,
            "Debug unlock error: Production invalid level"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_TOKEN_CHALLENGE,
            0xa0000006,
            "Debug unlock error: Production invalid token challenge"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_TOKEN_MBOX_CMD,
            0xa0000007,
            "Debug unlock error: Production invalid token mailbox command"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_TOKEN_WRONG_PUBLIC_KEYS,
            0xa0000008,
            "Debug unlock error: Production invalid token wrong public keys"
        ),
        (
            SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE,
            0xa0000009,
            "Debug unlock error: Production invalid token invalid signature"
        ),
        (
            SS_DBG_UNLOCK_REQ_IN_PASSIVE_MODE,
            0xa000000a,
            "Debug unlock error: Request in passive mode"
        ),
        (
            SS_DBG_UNLOCK_REQ_BIT_NOT_SET,
            0xa000000b,
            "Debug unlock error: Req bit not set in soc_ifc"
        ),
        (
            RUNTIME_DRIVER_AES_READ_KEY_KV_READ,
            0xa004_0001,
            "Driver Error: AES read key KV read"
        ),
        (
            RUNTIME_DRIVER_AES_READ_KEY_KV_WRITE,
            0xa004_0002,
            "Driver Error: AES read key KV write"
        ),
        (
            RUNTIME_DRIVER_AES_READ_KEY_KV_UNKNOWN,
            0xa004_0003,
            "Driver Error: AES read key KV unknown"
        ),
        (
            RUNTIME_DRIVER_AES_READ_DATA_KV_READ,
            0xa004_0004,
            "Driver Error: AES read data KV read"
        ),
        // 0xa004_0005 blank to match HMAC errors
        (
            RUNTIME_DRIVER_AES_READ_DATA_KV_UNKNOWN,
            0xa004_0006,
            "Driver Error: AES read data KV unknown"
        ),
        // 0xa004_0007-a blank to match HMAC errors
        (
            RUNTIME_DRIVER_AES_INVALID_STATE,
            0xa004_000b,
            "Driver Error: AES invalid state"
        ),
        (
            RUNTIME_DRIVER_AES_MAX_DATA,
            0xa004_000c,
            "Driver Error: AES max data exceeded"
        ),
        (
            RUNTIME_DRIVER_AES_INVALID_SLICE,
            0xa004_000d,
            "Driver Error: AES invalid slice"
        ),
        (
            RUNTIME_DRIVER_AES_INDEX_OUT_OF_BOUNDS,
            0xa004_000e,
            "Driver Error: AES index out of bounds"
        ),
        (
            RUNTIME_DRIVER_AES_INVALID_TAG_SIZE,
            0xa004_000f,
            "Driver Error: AES tag size is invalid"
        ),
        (
            RUNTIME_DRIVER_AES_ENGINE_BUSY,
            0xa004_0010,
            "Driver Error: AES engine is busy"
        ),
        (
            RUNTIME_DRIVER_AES_INVALID_TAG,
            0xa004_0011,
            "Driver Error: AES tag is invalid"
        ),
        // Skip to leave more error codes for the AES driver.
        (
            RUNTIME_DRIVER_PRECONDITIONED_KEY_INVALID_INPUT,
            0xa004_0020,
            "Driver Error: preconditioned key usage was invalid"
        ),
        (
            RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_ERROR,
            0xa004_0021,
            "Driver Error: preconditioned aes encrypt failed"
        ),
        (
            RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_INVALID_PARAM,
            0xa004_0022,
            "Driver Error: preconditioned aes encrypt invalid param"
        ),
        (
            RUNTIME_DRIVER_PRECONDITIONED_AES_DECRYPT_ERROR,
            0xa004_0023,
            "Driver Error: preconditioned aes decrypt failed"
        ),
        (
            RUNTIME_DRIVER_PRECONDITIONED_AES_DECRYPT_INVALID_PARAM,
            0xa004_0024,
            "Driver Error: preconditioned aes decrypt invalid param"
        ),
        (
            RUNTIME_DRIVER_AES_WRITE_KV,
            0xa004_0012,
            "Driver Error: AES output KV is invalid"
        ),
        (
            RUNTIME_DRIVER_HPKE_SEQ_EXHAUSTED,
            0xa004_1000,
            "Driver Error: HPKE sequence count exhausted"
        ),
        (
            RUNTIME_DRIVER_HPKE_SHAKE_INVALID_LABEL_LEN,
            0xa004_1001,
            "Driver Error: HPKE SHAKE label len was invalid"
        ),
        (
            RUNTIME_DRIVER_HPKE_ENCAP_TRNG_FAIL,
            0xa004_1002,
            "Driver Error: HPKE trng failed during encap"
        ),
        (
            RUNTIME_DRIVER_HPKE_CONVERT_INVALID_CIPHER_SUITE,
            0xa004_1003,
            "Driver Error: HPKE attempted to convert an invalid ciphersuite"
        ),
        (
            RUNTIME_DRIVER_HPKE_INVALID_PUB_KEY_BUFFER_SIZE,
            0xa004_1004,
            "Driver Error: HPKE the pub key buffer was too small"
        ),
        (
            RUNTIME_DRIVER_HPKE_ML_KEM_TRNG_KEYGEN_FAIL,
            0xa004_1100,
            "Driver Error: HPKE ml-kem failed to generate a key pair due to trng failure"
        ),
        (
            RUNTIME_DRIVER_HPKE_ML_KEM_PKR_DESERIALIZATION_FAIL,
            0xa004_1101,
            "Driver Error: HPKE ml-kem failed to deseriliaze the PKR in setup base s"
        ),
        (
            RUNTIME_DRIVER_HPKE_ML_KEM_ENCAP_SECRET_DESERIALIZATION_FAIL,
            0xa004_1102,
            "Driver Error: HPKE ml-kem failed to deseriliaze the encapsulated secret"
        ),
        (
            RUNTIME_DRIVER_HPKE_ML_KEM_ENCAP_KEY_SERIALIZATION_FAIL,
            0xa004_1103,
            "Driver Error: HPKE ml-kem failed to seriliaze the encap key"
        ),
        (
            RUNTIME_MAILBOX_SIGNATURE_MISMATCH,
            0xa005_0000,
            "Runtime Error: Signaure mismatch"
        ),
        (
            DOT_INVALID_KEY_TYPE,
            0xa005_5000,
            "DOT Error: Invalid key type"
        ),
        (
            CMB_HMAC_INVALID_ENC_CMK,
            0xa005_5020,
            "Crypto Mailbox Error: Invalid encrypted CMK"
        ),
        (
            CMB_HMAC_INVALID_DEC_CMK,
            0xa005_5021,
            "Crypto Mailbox Error: Invalid decrypted CMK"
        ),
        (
            CMB_HMAC_INVALID_KEY_USAGE,
            0xa005_5022,
            "Crypto Mailbox Error: Invalid key usage"
        ),
        (
            CMB_HMAC_INVALID_REQ_SIZE,
            0xa005_5023,
            "Crypto Mailbox Error: Invalid request size"
        ),
        (
            CMB_HMAC_INVALID_KEY_USAGE_AND_SIZE,
            0xa005_5024,
            "Crypto Mailbox Error: Invalid key usage and size"
        ),
        (
            CMB_HMAC_UNSUPPORTED_HASH_ALGORITHM,
            0xa005_5025,
            "Crypto Mailbox Error: Unsupported hash algorithm"
        ),
        (
            UDS_FE_ZEROIZATION_MARKER_NOT_CLEARED,
            0xa006_0000,
            "UDS FE Error: Zeroization marker not cleared"
        ),
        (
            UDS_FE_ZEROIZATION_SEED_NOT_CLEARED,
            0xa006_0001,
            "UDS FE Error: Zeroization seed not cleared"
        ),
        (
            UDS_FE_ZEROIZATION_DIGEST_NOT_CLEARED,
            0xa006_0002,
            "UDS FE Error: Zeroization digest not cleared"
        ),
        (
            UDS_FE_PROGRAMMING_SEED_LENGTH_ZERO,
            0xa006_0003,
            "UDS FE Error: Programming seed length zero"
        ),
        (
            UDS_FE_PROGRAMMING_ZEROIZATION_SUCCESS,
            0xa006_0004,
            "UDS FE Zeroization Success"
        ),
        (
            UDS_FE_PROGRAMMING_ZEROIZATION_FAILED,
            0xa006_0005,
            "UDS FE Zeroization Failed"
        )
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
