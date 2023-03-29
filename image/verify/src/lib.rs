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

    /// Owner public keys digest
    pub owner_pub_keys_digest: ImageDigest,

    /// First mutable code
    pub fmc: ImageVerificationExeInfo,

    /// Runtime
    pub runtime: ImageVerificationExeInfo,
}

/// Image Verification Environment
pub trait ImageVerificationEnv {
    type Image: Copy;

    /// Calculate SHA-384 Digest
    fn sha384_digest(
        &self,
        image: Self::Image,
        offset: u32,
        len: u32,
    ) -> CaliptraResult<ImageDigest>;

    /// Perform ECC-348 Verification
    fn ecc384_verify(
        &self,
        image: Self::Image,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<bool>;

    /// Get Vendor Public Key Digest
    fn vendor_pub_key_digest(&self, image: Self::Image) -> ImageDigest;

    /// Get Vendor Public Key Revocation list
    fn vendor_pub_key_revocation(&self, image: Self::Image) -> VendorPubKeyRevocation;

    /// Get Owner Public Key Digest
    fn owner_pub_key_digest(&self, image: Self::Image) -> ImageDigest;

    /// Get Anti-Rollback disable setting
    fn anti_rollback_disable(&self, image: Self::Image) -> bool;

    // Get Device Lifecycle state
    fn dev_lifecycle(&self, image: Self::Image) -> Lifecycle;
}
