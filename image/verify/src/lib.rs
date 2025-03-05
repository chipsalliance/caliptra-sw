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

pub const MAX_FIRMWARE_SVN: u32 = 128;

/// Image Verifification Executable Info
#[derive(Default, Debug)]
pub struct FirmwareSvnLogInfo {
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

    /// Digest of the image
    pub digest: ImageDigest384,
}

/// Information To Be Logged For The Verified Image
#[derive(Default, Debug)]
pub struct ImageVerificationLogInfo {
    // ECC Vendor Public Key Index To Log
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor ECC Public Key Revocation Fuse
    pub fuse_vendor_ecc_pub_key_revocation: VendorEccPubKeyRevocation,

    // PQC (LMS or MLDSA) Vendor Public Key Index
    pub vendor_pqc_pub_key_idx: u32,

    /// Vendor PQC (LMS or MLDSA) Public Key Revocation Fuse
    pub fuse_vendor_pqc_pub_key_revocation: u32,

    /// Firmware's SVN logging information
    pub fw_log_info: FirmwareSvnLogInfo,
}

/// Verified image information
#[derive(Default, Debug)]
pub struct ImageVerificationInfo {
    /// Vendor ECC public key index
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor PQC (LMS or MLDSA) public key index
    pub vendor_pqc_pub_key_idx: u32,

    /// PQC Key Type
    pub pqc_key_type: FwVerificationPqcKeyType,

    /// Digest of owner public keys that verified the image
    pub owner_pub_keys_digest: ImageDigest384,

    /// Whether `owner_pub_keys_digest` was in fuses
    pub owner_pub_keys_digest_in_fuses: bool,

    /// The SVN for this firmware bundle
    pub fw_svn: u32,

    /// The effective fuse SVN for this firmware bundle
    pub effective_fuse_svn: u32,

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
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest384>;

    /// Calculate SHA-512 Digest
    fn sha512_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest512>;

    /// Calculate SHA-384 Digest with accelerator
    fn sha384_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest384>;

    /// Calculate SHA-512 Digest with accelerator
    fn sha512_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest512>;

    /// Perform ECC-384 Verification
    fn ecc384_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>>;

    /// Perform LMS Verification
    fn lms_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>>;

    fn mldsa87_verify(
        &mut self,
        digest: &ImageDigest512,
        pub_key: &ImageMldsaPubKey,
        sig: &ImageMldsaSignature,
    ) -> CaliptraResult<Mldsa87Result>;

    /// Get Vendor Public Key Digest from fuses
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest384;

    /// Get Vendor ECC Public Key Revocation list
    fn vendor_ecc_pub_key_revocation(&self) -> VendorEccPubKeyRevocation;

    /// Get Vendor LMS Public Key Revocation list
    fn vendor_lms_pub_key_revocation(&self) -> u32;

    /// Get Vendor MLDSA Public Key Revocation list
    fn vendor_mldsa_pub_key_revocation(&self) -> u32;

    /// Get Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest384;

    /// Get Anti-Rollback disable setting
    fn anti_rollback_disable(&self) -> bool;

    // Get Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle;

    // Get the vendor ECC key index saved on cold boot in data vault
    fn vendor_ecc_pub_key_idx_dv(&self) -> u32;

    // Get the vendor PQC (LMS or MLDSA) key index saved on cold boot in data vault
    fn vendor_pqc_pub_key_idx_dv(&self) -> u32;

    // Get the owner key digest saved on cold boot in data vault
    fn owner_pub_key_digest_dv(&self) -> ImageDigest384;

    // Save the fmc digest in the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest384;

    // Get FW SVN fuse value
    fn fw_fuse_svn(&self) -> u32;

    // ICCM Range
    fn iccm_range(&self) -> Range<u32>;

    // Set the extended error code
    fn set_fw_extended_error(&mut self, err: u32);

    // Get the PQC Key Type from the fuse.
    fn pqc_key_type_fuse(&self) -> CaliptraResult<FwVerificationPqcKeyType>;
}
