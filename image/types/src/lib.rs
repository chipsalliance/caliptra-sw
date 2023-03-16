/*++

Licensed under the Apache-2.0 license.

File Name:

   lib.rs

Abstract:

    File contains data strucutres for the firmware image bundle.

--*/

#![cfg_attr(not(feature = "std"), no_std)]

use core::ops::Range;

use getset::{CopyGetters, Getters, MutGetters, Setters};
use memoffset::{offset_of, span_of};
use zerocopy::{AsBytes, FromBytes};

pub const MANIFEST_MARKER: u32 = 0x4E414D43;
pub const VENDOR_ECC_KEY_COUNT: u32 = 4;
pub const MAX_TOC_ENTRY_COUNT: u32 = 2;
pub const IMAGE_REVISION_BYTE_SIZE: usize = 20;
pub const ECC384_SCALAR_WORD_SIZE: usize = 12;
pub const ECC384_SCALAR_BYTE_SIZE: usize = 48;
pub const SHA384_DIGEST_WORD_SIZE: usize = 12;
pub const SHA384_DIGEST_BYTE_SIZE: usize = 48;
pub const IMAGE_BYTE_SIZE: usize = 128 * 1024;
pub const IMAGE_MANIFEST_BYTE_SIZE: usize = core::mem::size_of::<ImageManifest>();

pub type ImageScalar = [u32; ECC384_SCALAR_WORD_SIZE];
pub type ImageDigest = [u32; SHA384_DIGEST_WORD_SIZE];
pub type ImageRevision = [u8; IMAGE_REVISION_BYTE_SIZE];
pub type ImageEccPrivKey = ImageScalar;

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, Copy, Clone, Eq, PartialEq)]
pub struct ImageEccPubKey {
    /// X Coordinate
    #[getset(get = "pub", set = "pub")]
    pub x: ImageScalar,

    /// Y Coordinate
    #[getset(get = "pub", set = "pub")]
    pub y: ImageScalar,
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, Copy, Clone, Eq, PartialEq)]
pub struct ImageEccSignature {
    /// Random point
    #[getset(get = "pub", set = "pub")]
    pub r: ImageScalar,

    /// Proof
    #[getset(get = "pub", set = "pub")]
    pub s: ImageScalar,
}

/// Caliptra Image Bundle
#[cfg(feature = "std")]
#[derive(Debug, Default, Getters, Setters)]
pub struct ImageBundle {
    /// Manifest
    #[getset(get = "pub", set = "pub")]
    manifest: ImageManifest,

    /// FMC
    #[getset(get = "pub", set = "pub")]
    fmc: Vec<u8>,

    /// Runtime
    #[getset(get = "pub", set = "pub")]
    runtime: Vec<u8>,
}

/// Calipatra Image Manifest
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, MutGetters, CopyGetters)]
pub struct ImageManifest {
    /// Marker
    #[getset(get_copy = "pub", set = "pub")]
    marker: u32,

    /// Size of `Manifest` strucuture
    #[getset(get_copy = "pub", set = "pub")]
    size: u32,

    /// Preamle
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    preamble: ImagePreamble,

    /// Header
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    header: ImageHeader,

    /// First Mutable Code TOC Entry
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    fmc: ImageTocEntry,

    /// Runtime TOC Entry
    #[getset(get = "pub", get_mut = "pub", set = "pub")]
    runtime: ImageTocEntry,
}

impl ImageManifest {
    /// Returns the `Range<u32>` containing the vendor public keys
    pub fn vendor_pub_key_range() -> Range<u32> {
        let offset = offset_of!(ImageManifest, preamble) as u32;
        let span = span_of!(ImagePreamble, vendor_pub_keys);
        span.start as u32 + offset..span.end as u32 + offset
    }

    /// Returns `Range<u32>` containing the owner public key
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
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, MutGetters, Clone, Copy)]
pub struct ImageVendorPubKeys {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    ecc_pub_keys: [ImageEccPubKey; VENDOR_ECC_KEY_COUNT as usize],
    // TODO: Add LMS Public Keys here
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, MutGetters, Clone, Copy)]
pub struct ImageVendorPrivKeys {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    ecc_priv_keys: [ImageEccPrivKey; VENDOR_ECC_KEY_COUNT as usize],
    // TODO: Add LMS Private Keys here
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, MutGetters, Clone, Copy)]
pub struct ImageOwnerPubKeys {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    ecc_pub_key: ImageEccPubKey,
    // TODO: Add LMS Public Keys here
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, MutGetters, Setters)]
pub struct ImageOwnerPrivKeys {
    #[getset(get = "pub", set = "pub", get_mut = "pub")]
    ecc_priv_key: ImageEccPrivKey,
    // TODO: Add LMS Private Keys here
}

#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters)]
pub struct ImageSignatures {
    #[getset(get = "pub", set = "pub")]
    ecc_sig: ImageEccSignature,
    // TODO: Add LMS Signature here
}

/// Calipatra Image Bundle Preamble
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, CopyGetters)]
pub struct ImagePreamble {
    /// Vendor  Public Keys
    #[getset(get = "pub", set = "pub")]
    vendor_pub_keys: ImageVendorPubKeys,

    /// Vendor ECC Public Key Index
    #[getset(get_copy = "pub", set = "pub")]
    vendor_ecc_pub_key_idx: u32,

    /// Vendor Signatures
    #[getset(get = "pub", set = "pub")]
    vendor_sigs: ImageSignatures,

    /// Owner Public Key
    #[getset(get = "pub", set = "pub")]
    owner_pub_keys: ImageOwnerPubKeys,

    /// Owner Signatures
    #[getset(get = "pub", set = "pub")]
    owner_sigs: ImageSignatures,

    _rsvd: [u32; 2],
}

/// Caliptra Image header
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, CopyGetters)]
pub struct ImageHeader {
    /// Revision
    #[getset(get = "pub", set = "pub")]
    revision: [u32; 2],

    /// Vendor ECC Public Key Index
    #[getset(get_copy = "pub", set = "pub")]
    vendor_ecc_pub_key_idx: u32,

    /// Flags
    #[getset(get_copy = "pub", set = "pub")]
    flags: u32,

    /// TOC Entry Count
    #[getset(get_copy = "pub", set = "pub")]
    toc_len: u32,

    /// TOC Digest
    #[getset(get = "pub", set = "pub")]
    toc_digest: ImageDigest,
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
#[derive(AsBytes, FromBytes, Default, Debug, Getters, Setters, CopyGetters)]
pub struct ImageTocEntry {
    /// ID
    #[getset(get_copy = "pub", set = "pub")]
    id: u32,

    /// Type
    #[getset(get_copy = "pub", set = "pub")]
    r#type: u32,

    /// Commit revision
    #[getset(get = "pub", set = "pub")]
    revision: ImageRevision,

    /// Security Version Number
    #[getset(get_copy = "pub", set = "pub")]
    svn: u32,

    /// Minimum Security Version Number
    #[getset(get_copy = "pub", set = "pub")]
    min_svn: u32,

    /// Entry Point
    #[getset(get_copy = "pub", set = "pub")]
    load_addr: u32,

    /// Entry Point
    #[getset(get_copy = "pub", set = "pub")]
    entry_point: u32,

    /// Offset
    #[getset(get_copy = "pub", set = "pub")]
    offset: u32,

    /// Size
    #[getset(get_copy = "pub", set = "pub")]
    size: u32,

    /// Digest
    #[getset(get = "pub", set = "pub")]
    digest: ImageDigest,
}

impl ImageTocEntry {
    pub fn image_range(&self) -> Range<u32> {
        self.offset..self.offset + self.size
    }
}
