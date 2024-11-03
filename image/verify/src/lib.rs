/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    Caliptra Image Verification library.

--*/
#![cfg_attr(not(feature = "std"), no_std)]

mod verifier;

use caliptra_drivers::*;
use caliptra_image_types::*;
use core::ops::Range;

pub use verifier::ImageVerifier;

pub const MAX_RUNTIME_SVN: u32 = 128;

/// Image Verifification Executable Info
#[derive(Default, Debug)]
pub struct ImageSvnLogInfo {
    pub manifest_svn: u32,
    pub reserved: u32,
    pub fuse_svn: u32,
}

/// Image Verification Executable Info
#[derive(Default, Debug)]
pub struct ImageVerificationExeInfo {
    /// Load address
    pub load_addr: u32,

    /// Length
    pub size: u32,

    /// Entry Point
    pub entry_point: u32,

    /// Security version number
    pub svn: u32,

    /// The effective fuse SVN for this image
    pub effective_fuse_svn: u32,

    /// Digest of the image
    pub digest: ImageDigest,
}

/// Information To Be Logged For The Verified Image
#[derive(Default, Debug)]
pub struct ImageVerificationLogInfo {
    // ECC Vendor Public Key Index To Log
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor ECC Public Key Revocation Fuse
    pub fuse_vendor_ecc_pub_key_revocation: VendorPubKeyRevocation,

    // LMS Vendor Public Key Index
    pub vendor_lms_pub_key_idx: u32,

    /// Vendor LMS Public Key Revocation Fuse
    pub fuse_vendor_lms_pub_key_revocation: u32,

    /// First Mutable code's logging information
    pub fmc_log_info: ImageSvnLogInfo,

    /// Runtime Mutable code's logging information
    pub rt_log_info: ImageSvnLogInfo,
}

/// Verified image information
#[derive(Default, Debug)]
pub struct ImageVerificationInfo {
    /// Vendor ECC public key index
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor LMS public key index
    pub vendor_lms_pub_key_idx: u32,

    /// PQC Verification Configuration
    pub pqc_verify_config: RomPqcVerifyConfig,

    /// Digest of owner public keys that verified the image
    pub owner_pub_keys_digest: ImageDigest,

    /// Whether `owner_pub_keys_digest` was in fuses
    pub owner_pub_keys_digest_in_fuses: bool,

    /// First mutable code
    pub fmc: ImageVerificationExeInfo,

    /// Runtime
    pub runtime: ImageVerificationExeInfo,

    /// Information Returned To Be Logged
    pub log_info: ImageVerificationLogInfo,
}

/// Image Verification Environment
pub trait ImageVerificationEnv {
    /// Calculate SHA-384 Digest
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest>;

    /// Perform ECC-384 Verification
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>>;

    /// Perform LMS Verification
    fn lms_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>>;

    /// Get Vendor Public Key Digest from fuses
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest;

    /// Compute theVendor Public Key Digest from Image
    fn vendor_pub_key_info_digest_from_image(
        &mut self,
        ecc_key_desc: (u32, u32),
        ecc_pub_key_hashes: (u32, u32),
        lms_key_desc: (u32, u32),
        lms_pub_key_hashes: (u32, u32),
    ) -> CaliptraResult<ImageDigest>;

    /// Get Vendor ECC Public Key Revocation list
    fn vendor_ecc_pub_key_revocation(&self) -> VendorPubKeyRevocation;

    /// Get Vendor LMS Public Key Revocation list
    fn vendor_lms_pub_key_revocation(&self) -> u32;

    /// Get Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest;

    /// Get Anti-Rollback disable setting
    fn anti_rollback_disable(&self) -> bool;

    // Get Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle;

    // Get the vendor ECC key index saved on cold boot in data vault
    fn vendor_ecc_pub_key_idx_dv(&self) -> u32;

    // Get the vendor LMS key index saved on cold boot in data vault
    fn vendor_lms_pub_key_idx_dv(&self) -> u32;

    // Get the owner key digest saved on cold boot in data vault
    fn owner_pub_key_digest_dv(&self) -> ImageDigest;

    // Save the fmc digest in the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest;

    // Get Fuse FMC Key Manifest SVN
    fn fmc_fuse_svn(&self) -> u32;

    // Get Runtime fuse SVN
    fn runtime_fuse_svn(&self) -> u32;

    // ICCM Range
    fn iccm_range(&self) -> Range<u32>;

    // Set the extended error code
    fn set_fw_extended_error(&mut self, err: u32);
}
