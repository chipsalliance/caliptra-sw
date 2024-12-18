/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data structures for the image authorization manifest bundle.

--*/

#![no_std]

use bitfield::bitfield;
use caliptra_image_types::*;
use core::default::Default;
use core::ops::Range;
use memoffset::span_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

pub const AUTH_MANIFEST_MARKER: u32 = 0x4154_4D4E;
pub const AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT: usize = 127;

bitflags::bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct AuthManifestFlags : u32 {
        const VENDOR_SIGNATURE_REQUIRED = 0b1;
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

    pub flags: u32, // AuthManifestFlags(VENDOR_SIGNATURE_REQUIRED)

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

bitfield! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct ImageMetadataFlags(u32);
    pub image_source, set_image_source: 1, 0;
    pub ignore_auth_check, set_ignore_auth_check: 2;
}

/// Caliptra Authorization Manifest Image Metadata
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadata {
    pub fw_id: u32,

    pub flags: u32, // ImageMetadataFlags(image_source, ignore_auth_check)

    pub digest: [u8; 48],
}

impl Default for AuthManifestImageMetadata {
    fn default() -> Self {
        AuthManifestImageMetadata {
            fw_id: u32::MAX,
            flags: 0,
            digest: [0; 48],
        }
    }
}

/// Caliptra Authorization Manifest Image Metadata Collection
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadataCollection {
    pub entry_count: u32,

    pub image_metadata_list: [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
}

impl Default for AuthManifestImageMetadataCollection {
    fn default() -> Self {
        AuthManifestImageMetadataCollection {
            entry_count: 0,
            image_metadata_list: [AuthManifestImageMetadata::default();
                AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
        }
    }
}

/// Caliptra Image Authorization Manifest
#[repr(C)]
#[derive(AsBytes, FromBytes, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthorizationManifest {
    pub preamble: AuthManifestPreamble,

    pub image_metadata_col: AuthManifestImageMetadataCollection,
}
