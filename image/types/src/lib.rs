/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data structures for the firmware image bundle.

--*/

#![cfg_attr(not(feature = "std"), no_std)]

use caliptra_error::{CaliptraError, CaliptraResult};
use core::mem::size_of;
use core::ops::Range;
use zeroize::Zeroize;

use caliptra_lms_types::{
    LmotsAlgorithmType, LmotsSignature, LmsAlgorithmType, LmsPrivateKey, LmsPublicKey, LmsSignature,
};
use memoffset::{offset_of, span_of};
use zerocopy::{AsBytes, FromBytes};

pub const MANIFEST_MARKER: u32 = 0x4E414D43;
pub const KEY_DESCRIPTOR_VERSION: u16 = 1;
pub const VENDOR_ECC_MAX_KEY_COUNT: u32 = 4;
pub const VENDOR_LMS_MAX_KEY_COUNT: u32 = 32;
pub const VENDOR_MLDSA_MAX_KEY_COUNT: u32 = 4;
pub const VENDOR_PQC_MAX_KEY_COUNT: u32 = VENDOR_LMS_MAX_KEY_COUNT;
pub const MAX_TOC_ENTRY_COUNT: u32 = 2;
pub const IMAGE_REVISION_BYTE_SIZE: usize = 20;
pub const ECC384_SCALAR_WORD_SIZE: usize = 12;
pub const ECC384_SCALAR_BYTE_SIZE: usize = 48;
pub const SHA192_DIGEST_BYTE_SIZE: usize = 24;
pub const SHA192_DIGEST_WORD_SIZE: usize = 6;
pub const SHA256_DIGEST_WORD_SIZE: usize = 8;
pub const SHA384_DIGEST_WORD_SIZE: usize = 12;
pub const SHA384_DIGEST_BYTE_SIZE: usize = 48;
pub const SHA512_DIGEST_WORD_SIZE: usize = 16;
pub const IMAGE_LMS_OTS_P_PARAM: usize = 51;
pub const IMAGE_LMS_KEY_HEIGHT: usize = 15;
pub const IMAGE_BYTE_SIZE: usize = 128 * 1024;
// LMS-SHA192-H15
pub const IMAGE_LMS_TREE_TYPE: LmsAlgorithmType = LmsAlgorithmType::LmsSha256N24H15;
// LMOTS-SHA192-W4
pub const IMAGE_LMS_OTS_TYPE: LmotsAlgorithmType = LmotsAlgorithmType::LmotsSha256N24W4;
pub const IMAGE_MANIFEST_BYTE_SIZE: usize = core::mem::size_of::<ImageManifest>();
pub const MLDSA87_PUB_KEY_BYTE_SIZE: usize = 2592;
pub const MLDSA87_PUB_KEY_WORD_SIZE: usize = 648;
pub const MLDSA87_PRIV_KEY_BYTE_SIZE: usize = 4896;
pub const MLDSA87_PRIV_KEY_WORD_SIZE: usize = 1224;
pub const MLDSA87_SIGNATURE_BYTE_SIZE: usize = 4628;
pub const MLDSA87_SIGNATURE_WORD_SIZE: usize = 1157;
pub const MLDSA87_MSG_BYTE_SIZE: usize = 64;

pub const PQC_PUB_KEY_BYTE_SIZE: usize = MLDSA87_PUB_KEY_BYTE_SIZE;
pub const PQC_SIGNATURE_BYTE_SIZE: usize = MLDSA87_SIGNATURE_BYTE_SIZE;

pub type ImageScalar = [u32; ECC384_SCALAR_WORD_SIZE];
pub type ImageDigest384 = [u32; SHA384_DIGEST_WORD_SIZE];
pub type ImageDigest512 = [u32; SHA512_DIGEST_WORD_SIZE];
pub type ImageRevision = [u8; IMAGE_REVISION_BYTE_SIZE];
pub type ImageEccPrivKey = ImageScalar;

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageEccPubKey {
    /// X Coordinate
    pub x: ImageScalar,

    /// Y Coordinate
    pub y: ImageScalar,
}

pub type ImageLmsPublicKey = LmsPublicKey<SHA192_DIGEST_WORD_SIZE>;
pub type ImageLmsPrivKey = LmsPrivateKey<SHA192_DIGEST_WORD_SIZE>;

#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageMldsaPubKey(pub [u32; MLDSA87_PUB_KEY_WORD_SIZE]);

impl Default for ImageMldsaPubKey {
    fn default() -> Self {
        ImageMldsaPubKey([0; MLDSA87_PUB_KEY_WORD_SIZE])
    }
}

// impl ImageMldsaPubKey {
//     pub fn ref_from_prefix(bytes: &[u8]) -> Option<&Self> {
//         if bytes.len() >= size_of::<Self>() {
//             Some(unsafe { &*(bytes.as_ptr() as *const Self) })
//         } else {
//             None
//         }
//     }
// }

#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageMldsaPrivKey(pub [u32; MLDSA87_PRIV_KEY_WORD_SIZE]);

impl Default for ImageMldsaPrivKey {
    fn default() -> Self {
        ImageMldsaPrivKey([0; MLDSA87_PRIV_KEY_WORD_SIZE])
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImagePqcPubKey(pub [u8; PQC_PUB_KEY_BYTE_SIZE]);

impl Default for ImagePqcPubKey {
    fn default() -> Self {
        ImagePqcPubKey([0; PQC_PUB_KEY_BYTE_SIZE])
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageEccSignature {
    /// Random point
    pub r: ImageScalar,

    /// Proof
    pub s: ImageScalar,
}

pub type ImageLmsSignature =
    LmsSignature<SHA192_DIGEST_WORD_SIZE, IMAGE_LMS_OTS_P_PARAM, IMAGE_LMS_KEY_HEIGHT>;
pub type ImageLmOTSSignature = LmotsSignature<SHA192_DIGEST_WORD_SIZE, IMAGE_LMS_OTS_P_PARAM>;

#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageMldsaSignature(pub [u32; MLDSA87_SIGNATURE_WORD_SIZE]);

impl Default for ImageMldsaSignature {
    fn default() -> Self {
        ImageMldsaSignature([0; MLDSA87_SIGNATURE_WORD_SIZE])
    }
}

impl ImageMldsaSignature {
    pub fn ref_from_prefix(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() >= size_of::<Self>() {
            Some(unsafe { &*(bytes.as_ptr() as *const Self) })
        } else {
            None
        }
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Debug, Copy, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImagePqcSignature(pub [u8; PQC_SIGNATURE_BYTE_SIZE]);

impl Default for ImagePqcSignature {
    fn default() -> Self {
        ImagePqcSignature([0; PQC_SIGNATURE_BYTE_SIZE])
    }
}

// pub enum KeyType {
//     ECC = 1,
//     LMS = 2,
//     MLDSA = 3,
// }

// impl From<KeyType> for u8 {
//     fn from(val: KeyType) -> Self {
//         val as u8
//     }
// }

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum FwVerificationPqcKeyType {
    LMS = 1,
    MLDSA = 2,
}

impl From<FwVerificationPqcKeyType> for u8 {
    fn from(val: FwVerificationPqcKeyType) -> Self {
        val as u8
    }
}

impl Default for FwVerificationPqcKeyType {
    fn default() -> Self {
        Self::LMS
    }
}

impl FwVerificationPqcKeyType {
    pub fn from_u8(value: u8) -> Option<FwVerificationPqcKeyType> {
        match value {
            1 => Some(FwVerificationPqcKeyType::LMS),
            2 => Some(FwVerificationPqcKeyType::MLDSA),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ImageDigestHolder<'a> {
    pub digest_384: &'a ImageDigest384,
    pub digest_512: Option<&'a ImageDigest512>,
}

/// Caliptra Image Bundle
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct ImageBundle {
    /// Manifest
    pub manifest: ImageManifest,

    /// FMC
    pub fmc: Vec<u8>,

    /// Runtime
    pub runtime: Vec<u8>,
}

#[cfg(feature = "std")]
impl ImageBundle {
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        use std::io::ErrorKind;
        let mut result = vec![];
        result.extend_from_slice(self.manifest.as_bytes());
        if self.manifest.fmc.offset as usize != result.len() {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "actual fmc offset does not match manifest",
            ));
        }
        if self.manifest.fmc.size as usize != self.fmc.len() {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "actual fmc size does not match manifest",
            ));
        }
        result.extend_from_slice(&self.fmc);
        if self.manifest.runtime.offset as usize != result.len() {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "actual runtime offset does not match manifest",
            ));
        }
        if self.manifest.runtime.size as usize != self.runtime.len() {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "actual runtime size does not match manifest",
            ));
        }
        result.extend_from_slice(&self.runtime);
        Ok(result)
    }
}

/// Calipatra Image Manifest
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageManifest {
    /// Marker
    pub marker: u32,

    /// Size of `Manifest` structure
    pub size: u32,

    /// PQC key type for image verification (LMS or MLDSA keys)
    pub pqc_key_type: u8,

    pub reserved: [u8; 3],

    /// Preamble
    pub preamble: ImagePreamble,

    /// Header
    pub header: ImageHeader,

    /// First Mutable Code TOC Entry
    pub fmc: ImageTocEntry,

    /// Runtime TOC Entry
    pub runtime: ImageTocEntry,
}

impl Default for ImageManifest {
    fn default() -> Self {
        Self {
            marker: Default::default(),
            size: size_of::<ImageManifest>() as u32,
            pqc_key_type: 0,
            reserved: [0u8; 3],
            preamble: ImagePreamble::default(),
            header: ImageHeader::default(),
            fmc: ImageTocEntry::default(),
            runtime: ImageTocEntry::default(),
        }
    }
}
impl ImageManifest {
    /// Returns the `Range<u32>` containing the vendor public key descriptors
    pub fn vendor_pub_key_descriptors_range() -> Range<u32> {
        let offset = offset_of!(ImageManifest, preamble) as u32;
        let span = span_of!(ImagePreamble, vendor_pub_key_info);
        span.start as u32 + offset..span.end as u32 + offset
    }

    /// Returns the `Range<u32>` containing the owner public key
    pub fn owner_pub_key_range() -> Range<u32> {
        let offset = offset_of!(ImageManifest, preamble) as u32;
        let span = span_of!(ImagePreamble, owner_pub_keys);
        span.start as u32 + offset..span.end as u32 + offset
    }

    /// Returns `Range<u32>` containing the header
    pub fn header_range() -> Range<u32> {
        let span = span_of!(ImageManifest, header);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the table of contents
    pub fn toc_range() -> Range<u32> {
        let span = span_of!(ImageManifest, fmc..=runtime);
        span.start as u32..span.end as u32
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageVendorPubKeys {
    pub ecc_pub_keys: [ImageEccPubKey; VENDOR_ECC_MAX_KEY_COUNT as usize],
    #[zeroize(skip)]
    pub lms_pub_keys: [ImageLmsPublicKey; VENDOR_LMS_MAX_KEY_COUNT as usize],
    pub mldsa_pub_keys: [ImageMldsaPubKey; VENDOR_MLDSA_MAX_KEY_COUNT as usize],
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageVendorPubKeyInfo {
    pub ecc_key_descriptor: ImageEccKeyDescriptor,

    pub pqc_key_descriptor: ImagePqcKeyDescriptor,
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
pub struct ImageVendorPrivKeys {
    pub ecc_priv_keys: [ImageEccPrivKey; VENDOR_ECC_MAX_KEY_COUNT as usize],
    #[zeroize(skip)]
    pub lms_priv_keys: [ImageLmsPrivKey; VENDOR_LMS_MAX_KEY_COUNT as usize],
    pub mldsa_priv_keys: [ImageMldsaPrivKey; VENDOR_MLDSA_MAX_KEY_COUNT as usize],
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
pub struct OwnerPubKeyConfig {
    pub ecc_pub_key: ImageEccPubKey,
    #[zeroize(skip)]
    pub lms_pub_key: ImageLmsPublicKey,
    pub mldsa_pub_key: ImageMldsaPubKey,
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageOwnerPubKeys {
    pub ecc_pub_key: ImageEccPubKey,
    pub pqc_pub_key: ImagePqcPubKey,
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
pub struct ImageOwnerPrivKeys {
    pub ecc_priv_key: ImageEccPrivKey,
    #[zeroize(skip)]
    pub lms_priv_key: ImageLmsPrivKey,
    pub mldsa_priv_key: ImageMldsaPrivKey,
}

#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageSignatures {
    pub ecc_sig: ImageEccSignature,
    pub pqc_sig: ImagePqcSignature,
}

/// Caliptra Image ECC Key Descriptor
#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageEccKeyDescriptor {
    pub version: u16,
    pub reserved: u8,
    pub key_hash_count: u8,
    pub key_hash: ImageEccKeyHashes,
}

/// Caliptra Image LMS/MLDSA Key Descriptor
#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImagePqcKeyDescriptor {
    pub version: u16,
    pub key_type: u8,
    pub key_hash_count: u8,
    pub key_hash: ImagePqcKeyHashes,
}

pub type ImageEccKeyHashes = [ImageDigest384; VENDOR_ECC_MAX_KEY_COUNT as usize];
pub type ImagePqcKeyHashes = [ImageDigest384; VENDOR_PQC_MAX_KEY_COUNT as usize];

/// Caliptra Image Bundle Preamble
#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImagePreamble {
    /// Vendor Public Key Descriptor + Key Hashes
    pub vendor_pub_key_info: ImageVendorPubKeyInfo,

    /// Vendor ECC Public Key Index
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor Active Public Key
    pub vendor_ecc_active_pub_key: ImageEccPubKey,

    /// Vendor PQC Public Key Index
    pub vendor_pqc_pub_key_idx: u32,

    /// Vendor Active PQC (LMS or MLDSA) Public Key
    pub vendor_pqc_active_pub_key: ImagePqcPubKey,

    /// Vendor Signatures
    pub vendor_sigs: ImageSignatures,

    /// Owner Public Keys
    pub owner_pub_keys: ImageOwnerPubKeys,

    /// Owner Signatures
    pub owner_sigs: ImageSignatures,

    pub _rsvd: [u32; 2],
}

#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct VendorSignedData {
    /// Vendor Start Date [ASN1 Time Format] For FMC alias certificate.
    pub vendor_not_before: [u8; 15],

    /// Vendor End Date [ASN1 Time Format] For FMC alias certificate.
    pub vendor_not_after: [u8; 15],

    reserved: [u8; 10],
}

#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OwnerSignedData {
    /// Owner Start Date [ASN1 Time Format] For FMC alias certificate: Takes Preference over vendor start date
    pub owner_not_before: [u8; 15],

    /// Owner End Date [ASN1 Time Format] For FMC alias certificate: Takes Preference over vendor end date
    pub owner_not_after: [u8; 15],

    /// Owner epoch, used to diversify stable SVN keys.
    pub epoch: [u8; 2],

    reserved: [u8; 8],
}

/// Caliptra Image header
#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageHeader {
    /// Revision
    pub revision: [u32; 2],

    /// Vendor ECC Public Key Index
    pub vendor_ecc_pub_key_idx: u32,

    /// Vendor PQC Public Key Index
    pub vendor_pqc_pub_key_idx: u32,

    /// Flags
    /// Bit 0: Interpret the pl0_pauser field. If not set, all PAUSERs are PL1.
    pub flags: u32,

    /// TOC Entry Count
    pub toc_len: u32,

    /// The PAUSER with PL0 privileges. The SoC integration must choose
    /// only one PAUSER to be PL0.
    pub pl0_pauser: u32,

    /// TOC Digest
    pub toc_digest: ImageDigest384,

    /// Vendor Data
    pub vendor_data: VendorSignedData,

    /// The Signed owner data
    pub owner_data: OwnerSignedData,
}

/// Caliptra table contents entry id
pub enum ImageTocEntryType {
    /// First mutable code
    Executable = 1,
}

impl From<ImageTocEntryType> for u32 {
    /// Converts to this type from the input type.
    fn from(value: ImageTocEntryType) -> Self {
        value as u32
    }
}

/// Caliptra table contents entry id
pub enum ImageTocEntryId {
    /// First mutable code
    Fmc = 1,

    /// Runtime
    Runtime = 2,
}

impl From<ImageTocEntryId> for u32 {
    /// Converts to this type from the input type.
    fn from(value: ImageTocEntryId) -> Self {
        value as u32
    }
}

/// Caliptra Table of contents entry
#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ImageTocEntry {
    /// ID
    pub id: u32,

    /// Type
    pub r#type: u32,

    /// Commit revision
    pub revision: ImageRevision,

    // Firmware release number
    pub version: u32,

    /// Security Version Number
    /// Only read for Runtime entries. Not read for FMC.
    pub svn: u32,

    /// Reserved field
    pub reserved: u32,

    /// Entry Point
    pub load_addr: u32,

    /// Entry Point
    pub entry_point: u32,

    /// Offset
    pub offset: u32,

    /// Size
    pub size: u32,

    /// Digest
    pub digest: ImageDigest384,
}

impl ImageTocEntry {
    pub fn image_range(&self) -> CaliptraResult<Range<u32>> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_RANGE_ARITHMETIC_OVERFLOW;
        let end = self.offset.checked_add(self.size).ok_or(err)?;
        Ok(self.offset..end)
    }

    pub fn image_size(&self) -> u32 {
        self.size
    }

    pub fn overlaps(&self, other: &ImageTocEntry) -> bool {
        self.load_addr < (other.load_addr + other.image_size())
            && (self.load_addr + self.image_size()) > other.load_addr
    }
}

/// Information about the ROM image.
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug)]
pub struct RomInfo {
    // sha256 digest with big-endian words, where each 4-byte segment of the
    // digested data has the bytes reversed.
    pub sha256_digest: [u32; 8],
    pub revision: ImageRevision,
    pub flags: u32,
    pub version: u16,
    pub rsvd: u16, // maintain DWORD alignment
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_size() {
        assert_eq!(std::mem::size_of::<ImageManifest>() % 4, 0);
    }

    #[test]
    fn test_image_overlap() {
        let mut image1 = ImageTocEntry::default();
        let mut image2 = ImageTocEntry::default();

        // Case 1
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 450;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 2
        image1.load_addr = 450;
        image1.size = 100;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 3
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 499;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 4
        image1.load_addr = 499;
        image1.size = 100;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 5
        image1.load_addr = 499;
        image1.size = 1;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 6
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 499;
        image2.size = 1;
        assert!(image1.overlaps(&image2));

        // Case 7
        image1.load_addr = 400;
        image1.size = 1;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(image1.overlaps(&image2));

        // Case 8
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 400;
        image2.size = 1;
        assert!(image1.overlaps(&image2));

        // Case 9
        image1.load_addr = 399;
        image1.size = 1;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(!image1.overlaps(&image2));

        // Case 10
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 399;
        image2.size = 1;
        assert!(!image1.overlaps(&image2));

        // Case 11
        image1.load_addr = 500;
        image1.size = 100;
        image2.load_addr = 400;
        image2.size = 100;
        assert!(!image1.overlaps(&image2));

        // Case 12
        image1.load_addr = 400;
        image1.size = 100;
        image2.load_addr = 500;
        image2.size = 100;
        assert!(!image1.overlaps(&image2));
    }
}
