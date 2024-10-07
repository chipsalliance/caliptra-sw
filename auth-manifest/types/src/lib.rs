/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data structures for the image authorization manifest bundle.

--*/

#![no_std]

use core::ops::Range;

use caliptra_image_types::*;
use core::default::Default;
use memoffset::span_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

pub const AUTH_MANIFEST_MARKER: u32 = 0x4154_4D4E;
pub const AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT: usize = 16;

bitflags::bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct AuthManifestFlags : u32 {
        const VENDOR_SIGNATURE_REQURIED = 0b1;
    }
}

impl From<u32> for AuthManifestFlags {
    /// Converts to this type from the input type.
    fn from(value: u32) -> Self {
        AuthManifestFlags::from_bits_truncate(value)
    }
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestPubKeys {
    pub ecc_pub_key: ImageEccPubKey,
    #[zeroize(skip)]
    pub lms_pub_key: ImageLmsPublicKey,
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
pub struct AuthManifestPrivKeys {
    pub ecc_priv_key: ImageEccPrivKey,
    #[zeroize(skip)]
    pub lms_priv_key: ImageLmsPrivKey,
}

#[repr(C)]
#[derive(AsBytes, Clone, Copy, FromBytes, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestSignatures {
    pub ecc_sig: ImageEccSignature,
    #[zeroize(skip)]
    pub lms_sig: ImageLmsSignature,
}

/// Caliptra Authorization Image Manifest Preamble
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestPreamble {
    pub marker: u32,

    pub size: u32,

    pub version: u32,

    pub flags: u32,

    pub vendor_pub_keys: AuthManifestPubKeys,

    pub vendor_pub_keys_signatures: AuthManifestSignatures,

    pub owner_pub_keys: AuthManifestPubKeys,

    pub owner_pub_keys_signatures: AuthManifestSignatures,

    pub vendor_image_metdata_signatures: AuthManifestSignatures,

    pub owner_image_metdata_signatures: AuthManifestSignatures,
}

impl AuthManifestPreamble {
    /// Returns `Range<u32>` containing the version, flags and vendor manifest pub keys.
    pub fn vendor_signed_data_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, version..=vendor_pub_keys);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the vendor_pub_keys_signatures
    pub fn vendor_pub_keys_signatures_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, vendor_pub_keys_signatures);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the owner_pub_keys
    pub fn owner_pub_keys_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, owner_pub_keys);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the owner_pub_keys_signatures
    pub fn owner_pub_keys_signatures_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, owner_pub_keys_signatures);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the vendor_image_metdata_signatures
    pub fn vendor_image_metdata_signatures_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, vendor_image_metdata_signatures);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the owner_image_metdata_signatures
    pub fn owner_image_metdata_signatures_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, owner_image_metdata_signatures);
        span.start as u32..span.end as u32
    }
}

/// Caliptra Authorization Manifest Image Metadata
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadata {
    pub digest: [u8; 48],

    pub image_source: u32,
}

/// Caliptra Authorization Manifest Image Metadata Collection Header
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadataCollectionHeader {
    pub revision: u32,

    pub reserved: [u8; 12],

    pub entry_count: u32,
}

impl Default for AuthManifestImageMetadata {
    fn default() -> Self {
        AuthManifestImageMetadata {
            digest: [0; 48],
            image_source: 0,
        }
    }
}

/// Caliptra Authorization Manifest Image Metadata Collection
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadataCollection {
    pub header: AuthManifestImageMetadataCollectionHeader,

    pub image_metadata_list: [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
}

/// Caliptra Image Authorization Manifest
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthorizationManifest {
    pub preamble: AuthManifestPreamble,

    pub image_metadata_col: AuthManifestImageMetadataCollection,
}
