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

    pub const DRIVER_BAD_DATASTORE_VAULT_TYPE: CaliptraError = CaliptraError::new_const(0x00010001);
    pub const DRIVER_BAD_DATASTORE_REG_TYPE: CaliptraError = CaliptraError::new_const(0x00010002);

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
    pub const DRIVER_ECC384_KEYGEN_PAIRWISE_CONSISTENCY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x0005000d);
    pub const DRIVER_ECC384_SIGN_VALIDATION_FAILED: CaliptraError =
        CaliptraError::new_const(0x0005000e);
    pub const DRIVER_ECC384_SCALAR_RANGE_CHECK_FAILED: CaliptraError =
        CaliptraError::new_const(0x0005000f);

    pub const DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00060001);
    pub const DRIVER_KV_ERASE_WRITE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00060002);

    pub const DRIVER_PCR_BANK_ERASE_WRITE_LOCK_SET_FAILURE: CaliptraError =
        CaliptraError::new_const(0x00070001);

    /// Mailbox Errors
    pub const DRIVER_MAILBOX_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x00080001);
    pub const DRIVER_MAILBOX_INVALID_DATA_LEN: CaliptraError = CaliptraError::new_const(0x00080002);
    pub const DRIVER_MAILBOX_ENQUEUE_ERR: CaliptraError = CaliptraError::new_const(0x00080004);

    /// SHA384ACC Errors.
    pub const DRIVER_SHA384ACC_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x00090003);
    /// SHA1 Errors.
    pub const DRIVER_SHA1_INVALID_STATE: CaliptraError = CaliptraError::new_const(0x000a0001);
    pub const DRIVER_SHA1_MAX_DATA: CaliptraError = CaliptraError::new_const(0x000a0002);
    pub const DRIVER_SHA1_INVALID_SLICE: CaliptraError = CaliptraError::new_const(0x000a0003);
    pub const DRIVER_SHA1_INDEX_OUT_OF_BOUNDS: CaliptraError = CaliptraError::new_const(0x000a0004);

    /// Image Verifier Errors
    pub const IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0001);
    pub const IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0002);
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0003);
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0004);
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0005);
    pub const IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0006);
    pub const IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0007);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x000b0008);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED: CaliptraError =
        CaliptraError::new_const(0x000b0009);
    pub const IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000a);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000b);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b000c);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b000d);
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b000e);
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b000f);
    pub const IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0010);
    pub const IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURES: CaliptraError =
        CaliptraError::new_const(0x000b0011);
    pub const IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0012);
    pub const IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0013);
    pub const IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0014);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0015);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0016);
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP: CaliptraError =
        CaliptraError::new_const(0x000b0017);
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER: CaliptraError =
        CaliptraError::new_const(0x000b0018);
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b0019);
    pub const IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b001a);
    pub const IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b001b);
    pub const IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG: CaliptraError =
        CaliptraError::new_const(0x000b001c);
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b001d);
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PUB_KEY_IDX_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b001e);
    pub const IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b001f);
    pub const IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0021);
    pub const IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0022);
    pub const IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0023);
    pub const IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0024);
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b0025);
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b0026);
    pub const IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE: CaliptraError =
        CaliptraError::new_const(0x000b0027);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0028);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b0029);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b002a);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED: CaliptraError =
        CaliptraError::new_const(0x000b002b);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b002c);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED: CaliptraError =
        CaliptraError::new_const(0x000b002d);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE: CaliptraError =
        CaliptraError::new_const(0x000b002e);
    pub const IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE: CaliptraError =
        CaliptraError::new_const(0x000b002f);
    pub const IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x000b0030);
    pub const IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0031);
    pub const IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_OUT_OF_BOUNDS: CaliptraError =
        CaliptraError::new_const(0x000b0032);
    pub const IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0033);
    pub const IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP: CaliptraError =
        CaliptraError::new_const(0x000b0034);
    pub const IMAGE_VERIFIER_ERR_OWNER_LMS_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x000b0036);
    pub const IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID: CaliptraError =
        CaliptraError::new_const(0x000b0038);
    pub const RUNTIME_HANDOFF_FHT_NOT_LOADED: CaliptraError = CaliptraError::new_const(0x000b0039);
    pub const IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_REVOKED: CaliptraError =
        CaliptraError::new_const(0x000b0003a);
    pub const IMAGE_VERIFIER_ERR_FMC_SIZE_ZERO: CaliptraError =
        CaliptraError::new_const(0x000b003b);
    pub const IMAGE_VERIFIER_ERR_RUNTIME_SIZE_ZERO: CaliptraError =
        CaliptraError::new_const(0x000b003c);

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

    pub const DRIVER_LMS_INVALID_SIGNATURE_LENGTH: CaliptraError =
        CaliptraError::new_const(0x000c000a);
    pub const DRIVER_LMS_INVALID_PUBLIC_KEY_LENGTH: CaliptraError =
        CaliptraError::new_const(0x000c000b);
    pub const DRIVER_LMS_INVALID_SIGNATURE_DEPTH: CaliptraError =
        CaliptraError::new_const(0x000c000c);

    pub const DRIVER_LMS_SIGNATURE_LMOTS_DOESNT_MATCH_PUBKEY_LMOTS: CaliptraError =
        CaliptraError::new_const(0x000c000d);

    /// CSRNG Errors
    pub const DRIVER_CSRNG_INSTANTIATE: CaliptraError = CaliptraError::new_const(0x000d0001);
    pub const DRIVER_CSRNG_UNINSTANTIATE: CaliptraError = CaliptraError::new_const(0x000d0002);
    pub const DRIVER_CSRNG_RESEED: CaliptraError = CaliptraError::new_const(0x000d0003);
    pub const DRIVER_CSRNG_GENERATE: CaliptraError = CaliptraError::new_const(0x000d0004);
    pub const DRIVER_CSRNG_UPDATE: CaliptraError = CaliptraError::new_const(0x000d0005);
    pub const DRIVER_CSRNG_OTHER_HEALTH_CHECK_FAILED: CaliptraError =
        CaliptraError::new_const(0x000d0006);
    pub const DRIVER_CSRNG_REPCNT_HEALTH_CHECK_FAILED: CaliptraError =
        CaliptraError::new_const(0x000d0007);
    pub const DRIVER_CSRNG_ADAPTP_HEALTH_CHECK_FAILED: CaliptraError =
        CaliptraError::new_const(0x000d0008);

    pub const DRIVER_HANDOFF_INVALID_VAULT: CaliptraError = CaliptraError::new_const(0x000D100);
    pub const DRIVER_HANDOFF_INVALID_KEY_ID: CaliptraError = CaliptraError::new_const(0x000D101);
    pub const DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY4: CaliptraError =
        CaliptraError::new_const(0x000D102);
    pub const DRIVER_HANDOFF_INVALID_COLD_RESET_ENTRY48: CaliptraError =
        CaliptraError::new_const(0x000D103);
    pub const DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY4: CaliptraError =
        CaliptraError::new_const(0x000D104);
    pub const DRIVER_HANDOFF_INVALID_WARM_RESET_ENTRY48: CaliptraError =
        CaliptraError::new_const(0x000D104);

    /// Runtime Errors
    pub const RUNTIME_INTERNAL: CaliptraError = CaliptraError::new_const(0x000E0001);
    pub const RUNTIME_UNIMPLEMENTED_COMMAND: CaliptraError = CaliptraError::new_const(0x000E0002);
    pub const RUNTIME_INSUFFICIENT_MEMORY: CaliptraError = CaliptraError::new_const(0x000E0003);
    pub const RUNTIME_ECDSA_VERIFY_FAILED: CaliptraError = CaliptraError::new_const(0x000E0004);
    pub const RUNTIME_INVALID_CHECKSUM: CaliptraError = CaliptraError::new_const(0x000E0005);
    pub const RUNTIME_FIPS_UNIMPLEMENTED: CaliptraError = CaliptraError::new_const(0x000E0006);
    pub const RUNTIME_UNEXPECTED_UPDATE_RETURN: CaliptraError =
        CaliptraError::new_const(0x000E0007);
    pub const RUNTIME_SHUTDOWN: CaliptraError = CaliptraError::new_const(0x000E0008);
    pub const RUNTIME_NO_MANIFEST: CaliptraError = CaliptraError::new_const(0x000E0009);
    pub const RUNTIME_MAILBOX_INVALID_PARAMS: CaliptraError = CaliptraError::new_const(0x000E000A);
    pub const RUNTIME_GLOBAL_NMI: CaliptraError = CaliptraError::new_const(0x000E000B);
    pub const RUNTIME_GLOBAL_EXCEPTION: CaliptraError = CaliptraError::new_const(0x000E000C);
    pub const RUNTIME_GLOBAL_PANIC: CaliptraError = CaliptraError::new_const(0x000E000D);
    pub const RUNTIME_HMAC_VERIFY_FAILED: CaliptraError = CaliptraError::new_const(0x000E000E);
    pub const RUNTIME_INVOKE_DPE_FAILED: CaliptraError = CaliptraError::new_const(0x000E000F);
    pub const RUNTIME_INITIALIZE_DPE_FAILED: CaliptraError = CaliptraError::new_const(0x000E0010);
    pub const RUNTIME_DISABLE_ATTESTATION_FAILED: CaliptraError =
        CaliptraError::new_const(0x000E0011);
    pub const RUNTIME_HANDOFF_INVALID_PARM: CaliptraError = CaliptraError::new_const(0x000E0012);
    pub const RUNTIME_GET_DEVID_CERT_FAILED: CaliptraError = CaliptraError::new_const(0x000E0013);
    pub const RUNTIME_CERT_CHAIN_CREATION_FAILED: CaliptraError =
        CaliptraError::new_const(0x000E0014);
    pub const RUNTIME_SELF_TEST_IN_PROGRESS: CaliptraError = CaliptraError::new_const(0x000E0015);
    pub const RUNTIME_SELF_TEST_NOT_STARTED: CaliptraError = CaliptraError::new_const(0x000E0016);
    pub const RUNTIME_INVALID_FMC_SIZE: CaliptraError = CaliptraError::new_const(0x000E0017);
    pub const RUNTIME_INVALID_RUNTIME_SIZE: CaliptraError = CaliptraError::new_const(0x000E0018);

    /// FMC Errors
    pub const FMC_GLOBAL_NMI: CaliptraError = CaliptraError::new_const(0x000F0001);
    pub const FMC_GLOBAL_EXCEPTION: CaliptraError = CaliptraError::new_const(0x000F0002);
    pub const FMC_GLOBAL_PANIC: CaliptraError = CaliptraError::new_const(0x000F0003);
    pub const FMC_HANDOFF_INVALID_PARAM: CaliptraError = CaliptraError::new_const(0x000F0004);
    pub const FMC_RT_ALIAS_DERIVE_FAILURE: CaliptraError = CaliptraError::new_const(0x000F0005);
    pub const FMC_RT_ALIAS_CERT_VERIFY: CaliptraError = CaliptraError::new_const(0x000F0006);
    pub const FMC_RT_ALIAS_TBS_SIZE_EXCEEDED: CaliptraError = CaliptraError::new_const(0x000F0007);
    pub const FMC_CDI_KV_COLLISION: CaliptraError = CaliptraError::new_const(0x000F0008);
    pub const FMC_ALIAS_KV_COLLISION: CaliptraError = CaliptraError::new_const(0x000F0009);

    /// TRNG_EXT Errors
    pub const DRIVER_TRNG_EXT_TIMEOUT: CaliptraError = CaliptraError::new_const(0x00100001);

    /// SOC_IFC driver Errors
    pub const DRIVER_SOC_IFC_INVALID_TIMER_CONFIG: CaliptraError =
        CaliptraError::new_const(0x00100001);

    /// Bounded address Errors
    pub const ADDRESS_MISALIGNED: CaliptraError = CaliptraError::new_const(0x00110000);
    pub const ADDRESS_NOT_IN_ROM: CaliptraError = CaliptraError::new_const(0x00110001);

    /// Initial Device ID Errors
    pub const ROM_IDEVID_CSR_BUILDER_INIT_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000001);
    pub const ROM_IDEVID_CSR_BUILDER_BUILD_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000002);
    pub const ROM_IDEVID_INVALID_CSR: CaliptraError = CaliptraError::new_const(0x01000003);
    pub const ROM_IDEVID_CSR_VERIFICATION_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01000004);
    pub const ROM_IDEVID_CSR_OVERFLOW: CaliptraError = CaliptraError::new_const(0x01000005);

    /// ROM Local Device ID Errors
    pub const ROM_LDEVID_CSR_VERIFICATION_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01010001);

    /// Firmware Processor Errors
    pub const FW_PROC_MANIFEST_READ_FAILURE: CaliptraError = CaliptraError::new_const(0x01020001);
    pub const FW_PROC_INVALID_IMAGE_SIZE: CaliptraError = CaliptraError::new_const(0x01020002);
    pub const FW_PROC_MAILBOX_STATE_INCONSISTENT: CaliptraError =
        CaliptraError::new_const(0x01020003);
    pub const FW_PROC_MAILBOX_INVALID_COMMAND: CaliptraError = CaliptraError::new_const(0x01020004);

    /// FMC Alias Layer : Certificate Verification Failure.
    pub const FMC_ALIAS_CERT_VERIFY: CaliptraError = CaliptraError::new_const(0x01030001);

    /// Update Reset Errors
    pub const ROM_UPDATE_RESET_FLOW_MANIFEST_READ_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01040002);
    pub const ROM_UPDATE_RESET_FLOW_INVALID_FIRMWARE_COMMAND: CaliptraError =
        CaliptraError::new_const(0x01040003);
    pub const ROM_UPDATE_RESET_FLOW_MAILBOX_ACCESS_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01040004);
    pub const ROM_UPDATE_RESET_READ_FHT_FAILURE: CaliptraError =
        CaliptraError::new_const(0x01040005);

    // Warm Reset Errors
    pub const ROM_WARM_RESET_UNSUCCESSFUL_PREVIOUS_COLD_RESET: CaliptraError =
        CaliptraError::new_const(0x01040010);

    /// Unknown Reset Error
    pub const ROM_UNKNOWN_RESET_FLOW: CaliptraError = CaliptraError::new_const(0x01040020);

    /// ROM CFI Errors
    pub const ROM_CFI_PANIC_UNKNOWN: CaliptraError = CaliptraError::new_const(0x1040050);
    pub const ROM_CFI_PANIC_COUNTER_CORRUPT: CaliptraError = CaliptraError::new_const(0x1040051);
    pub const ROM_CFI_PANIC_COUNTER_OVERFLOW: CaliptraError = CaliptraError::new_const(0x1040052);
    pub const ROM_CFI_PANIC_COUNTER_UNDERFLOW: CaliptraError = CaliptraError::new_const(0x1040053);
    pub const ROM_CFI_PANIC_COUNTER_MISMATCH: CaliptraError = CaliptraError::new_const(0x1040054);
    pub const ROM_CFI_PANIC_ASSERT_EQ_FAILURE: CaliptraError = CaliptraError::new_const(0x1040055);
    pub const ROM_CFI_PANIC_ASSERT_NE_FAILURE: CaliptraError = CaliptraError::new_const(0x1040056);
    pub const ROM_CFI_PANIC_ASSERT_GT_FAILURE: CaliptraError = CaliptraError::new_const(0x1040057);
    pub const ROM_CFI_PANIC_ASSERT_LT_FAILURE: CaliptraError = CaliptraError::new_const(0x1040058);
    pub const ROM_CFI_PANIC_ASSERT_GE_FAILURE: CaliptraError = CaliptraError::new_const(0x1040059);
    pub const ROM_CFI_PANIC_ASSERT_LE_FAILURE: CaliptraError = CaliptraError::new_const(0x104005A);
    pub const ROM_CFI_PANIC_TRNG_FAILURE: CaliptraError = CaliptraError::new_const(0x104005B);

    /// ROM Global Errors
    pub const ROM_GLOBAL_NMI: CaliptraError = CaliptraError::new_const(0x01050001);
    pub const ROM_GLOBAL_EXCEPTION: CaliptraError = CaliptraError::new_const(0x01050002);
    pub const ROM_GLOBAL_PANIC: CaliptraError = CaliptraError::new_const(0x01050003);
    pub const ROM_GLOBAL_PCR_LOG_INVALID_ENTRY_ID: CaliptraError =
        CaliptraError::new_const(0x01050004);
    pub const ROM_GLOBAL_PCR_LOG_UNSUPPORTED_DATA_LENGTH: CaliptraError =
        CaliptraError::new_const(0x01050005);
    pub const ROM_GLOBAL_PCR_LOG_EXHAUSTED: CaliptraError = CaliptraError::new_const(0x01050006);

    pub const ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID: CaliptraError =
        CaliptraError::new_const(0x01050007);
    pub const ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH: CaliptraError =
        CaliptraError::new_const(0x01050008);

    pub const ROM_GLOBAL_UNSUPPORTED_LDEVID_TBS_SIZE: CaliptraError =
        CaliptraError::new_const(0x01050009);
    pub const ROM_GLOBAL_UNSUPPORTED_FMCALIAS_TBS_SIZE: CaliptraError =
        CaliptraError::new_const(0x0105000A);

    pub const ROM_GLOBAL_FAKE_ROM_IN_PRODUCTION: CaliptraError =
        CaliptraError::new_const(0x0105000B);

    /// ROM KAT Errors
    pub const ROM_KAT_SHA256_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90010001);
    pub const ROM_KAT_SHA256_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90010002);

    pub const ROM_KAT_SHA384_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90020001);
    pub const ROM_KAT_SHA384_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90020002);

    pub const ROM_KAT_HMAC384_FAILURE: CaliptraError = CaliptraError::new_const(0x90030001);
    pub const ROM_KAT_HMAC384_TAG_MISMATCH: CaliptraError = CaliptraError::new_const(0x90030002);

    pub const ROM_KAT_ECC384_SIGNATURE_GENERATE_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90040001);
    pub const ROM_KAT_ECC384_SIGNATURE_VERIFY_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90040002);
    pub const ROM_KAT_ECC384_SIGNATURE_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x90040003);

    pub const ROM_KAT_SHA384_ACC_DIGEST_START_OP_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90050001);
    pub const ROM_KAT_SHA384_ACC_DIGEST_FAILURE: CaliptraError =
        CaliptraError::new_const(0x90050002);
    pub const ROM_KAT_SHA384_ACC_DIGEST_MISMATCH: CaliptraError =
        CaliptraError::new_const(0x90050003);

    pub const ROM_KAT_SHA1_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90060001);
    pub const ROM_KAT_SHA1_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90060002);

    pub const ROM_KAT_LMS_DIGEST_FAILURE: CaliptraError = CaliptraError::new_const(0x90070001);
    pub const ROM_KAT_LMS_DIGEST_MISMATCH: CaliptraError = CaliptraError::new_const(0x90070002);

    pub const ROM_INTEGRITY_FAILURE: CaliptraError = CaliptraError::new_const(0x90080001);
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

    #[test]
    fn test_try_from() {
        assert!(CaliptraError::try_from(0).is_err());
        assert_eq!(
            Ok(CaliptraError::DRIVER_SHA256_INVALID_STATE),
            CaliptraError::try_from(0x00020001)
        );
    }
}
