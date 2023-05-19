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

/// Image Verifification Executable Info
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

    /// Digest of the image
    pub digest: ImageDigest,
}

/// Verified image information
#[derive(Default, Debug)]
pub struct ImageVerificationInfo {
    /// Vendor ECC public key index
    pub vendor_ecc_pub_key_idx: u32,

    /// Digest of vendor public keys that verified the image
    pub vendor_pub_keys_digest: ImageDigest,

    /// Digest of owner public keys that verified the image
    pub owner_pub_keys_digest: ImageDigest,

    /// First mutable code
    pub fmc: ImageVerificationExeInfo,

    /// Runtime
    pub runtime: ImageVerificationExeInfo,
}

/// Image Verification Environment
pub trait ImageVerificationEnv {
    /// Calculate SHA-384 Digest
    fn sha384_digest(&self, offset: u32, len: u32) -> CaliptraResult<ImageDigest>;

    /// Perform ECC-348 Verification
    fn ecc384_verify(
        &self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<bool>;

    /// Get Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest;

    /// Get Vendor Public Key Revocation list
    fn vendor_pub_key_revocation(&self) -> VendorPubKeyRevocation;

    /// Get Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest;

    /// Get Anti-Rollback disable setting
    fn anti_rollback_disable(&self) -> bool;

    // Get Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle;

    // Get the vendor key index saved on cold boot in data vault
    fn vendor_pub_key_idx_dv(&self) -> u32;

    // Get the owner key digest saved on cold boot in data vault
    fn owner_pub_key_digest_dv(&self) -> ImageDigest;

    // Save the fmc digest in the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest;

    // Get Fuse FMC Key Manifest SVN
    fn fmc_svn(&self) -> u32;

    // Get Runtime fuse SVN
    fn runtime_svn(&self) -> u32;

    // ICCM Range
    fn iccm_range(&self) -> Range<u32>;
}
