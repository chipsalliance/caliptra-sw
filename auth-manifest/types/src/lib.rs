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
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

pub const AUTH_MANIFEST_MARKER: u32 = 0x324D_5441;
pub const AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT: usize = 127;
// Preamble size grew by the Vendor Ext field: `vendor_ext_size: u32` (4) +
// `vendor_ext: AuthManifestVendorExt([u8; AUTH_MANIFEST_VENDOR_EXT_MAX_SIZE])` (256) = 260 bytes.
// Previous (v1, no Vendor Ext) value was 24292.
pub const AUTH_MANIFEST_PREAMBLE_SIZE: usize = 24552;

/// Auth manifest format version that carries the Vendor Ext field.
pub const AUTH_MANIFEST_VERSION_V2: u32 = 2;

/// Fixed size (bytes) of the Vendor Ext data region. The meaningful length is
/// given by `AuthManifestPreamble::vendor_ext_size`; the remaining bytes are padding.
pub const AUTH_MANIFEST_VENDOR_EXT_MAX_SIZE: usize = 256;

// Vendor Ext TLV record ids (`id: u16 LE ‖ len: u16 LE ‖ value`).
/// End / padding marker.
pub const VENDOR_EXT_ID_END: u16 = 0x0000;
/// Vendor-unique command authentication public-key hash (48 bytes,
/// `SHA-384(cmd_ecc_pub ‖ cmd_mldsa_pub)`).
pub const VENDOR_EXT_ID_AUTH_PK_HASH: u16 = 0x0001;
// 0x0002 is reserved for the in-field vendor-key revocation record (separate RFC);
// it is intentionally not defined or parsed here.

/// Byte length of the `0x0001` command-auth PK-hash value (SHA-384 digest).
pub const VENDOR_EXT_AUTH_PK_HASH_LEN: usize = 48;

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
#[derive(IntoBytes, FromBytes, Default, Debug, Clone, Copy, Zeroize)]
pub struct AuthManifestPubKeysConfig {
    pub ecc_pub_key: ImageEccPubKey,
    #[zeroize(skip)]
    pub lms_pub_key: ImageLmsPublicKey,
    pub mldsa_pub_key: ImageMldsaPubKey,
}

#[repr(C)]
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Default, Debug, Clone, Copy, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestPubKeys {
    pub ecc_pub_key: ImageEccPubKey,
    pub pqc_pub_key: ImagePqcPubKey,
}

#[repr(C)]
#[derive(IntoBytes, FromBytes, KnownLayout, Immutable, Default, Debug, Clone, Copy, Zeroize)]
pub struct AuthManifestPrivKeysConfig {
    pub ecc_priv_key: ImageEccPrivKey,
    #[zeroize(skip)]
    pub lms_priv_key: ImageLmsPrivKey,
    pub mldsa_priv_key: ImageMldsaPrivKey,
}

#[repr(C)]
#[derive(IntoBytes, Clone, Copy, FromBytes, Immutable, KnownLayout, Default, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestSignatures {
    pub ecc_sig: ImageEccSignature,
    pub pqc_sig: ImagePqcSignature,
}

/// Vendor Ext data region of the Auth Manifest preamble.
///
/// A fixed-size buffer holding packed TLV records (`id: u16 LE ‖ len: u16 LE ‖ value`).
/// The meaningful length is `AuthManifestPreamble::vendor_ext_size`; the remaining bytes
/// are padding. Fixed size keeps `AuthManifestPreamble` a single `ref_from_bytes` parse.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq, Zeroize,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestVendorExt(pub [u8; AUTH_MANIFEST_VENDOR_EXT_MAX_SIZE]);

impl Default for AuthManifestVendorExt {
    fn default() -> Self {
        AuthManifestVendorExt([0; AUTH_MANIFEST_VENDOR_EXT_MAX_SIZE])
    }
}

/// Caliptra Authorization Image Manifest Preamble
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestPreamble {
    pub marker: u32,

    pub size: u32,

    pub version: u32,

    pub svn: u32,

    pub flags: u32, // AuthManifestFlags(VENDOR_SIGNATURE_REQUIRED)

    // Vendor Ext (added after `flags`, before `vendor_pub_keys`, so it falls inside
    // `vendor_signed_data_range` = version..=vendor_pub_keys and is covered by the
    // existing vendor signature — no extra signature, no new fuse).
    /// Number of meaningful bytes in `vendor_ext` (rest is padding).
    pub vendor_ext_size: u32,

    /// Packed Vendor Ext TLV records (see `AuthManifestVendorExt`).
    pub vendor_ext: AuthManifestVendorExt,

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

    /// Parses the Vendor Ext data as packed TLV records and returns the value of the
    /// `VENDOR_EXT_ID_AUTH_PK_HASH` (`0x0001`) record, if present.
    ///
    /// Record format: `id: u16 LE ‖ len: u16 LE ‖ value[len]`. Unknown ids are skipped
    /// by their length (forward-compatible). A `VENDOR_EXT_ID_END` (`0x0000`) record or a
    /// truncated/overrunning record terminates the walk. Returns `None` if the `0x0001`
    /// record is absent or its length is not `VENDOR_EXT_AUTH_PK_HASH_LEN` (48).
    pub fn vendor_ext_auth_pk_hash(&self) -> Option<[u8; VENDOR_EXT_AUTH_PK_HASH_LEN]> {
        let len = self.vendor_ext_size as usize;
        if len > AUTH_MANIFEST_VENDOR_EXT_MAX_SIZE {
            return None;
        }
        let data = &self.vendor_ext.0[..len];
        let mut off = 0usize;
        // Each record has a 4-byte header (id + len).
        while off + 4 <= data.len() {
            let id = u16::from_le_bytes([data[off], data[off + 1]]);
            let vlen = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
            if id == VENDOR_EXT_ID_END {
                break;
            }
            let val_start = off + 4;
            let val_end = val_start.checked_add(vlen)?;
            if val_end > data.len() {
                // Truncated / overrunning record — stop.
                break;
            }
            if id == VENDOR_EXT_ID_AUTH_PK_HASH {
                if vlen != VENDOR_EXT_AUTH_PK_HASH_LEN {
                    return None;
                }
                let mut out = [0u8; VENDOR_EXT_AUTH_PK_HASH_LEN];
                out.copy_from_slice(&data[val_start..val_end]);
                return Some(out);
            }
            off = val_end;
        }
        None
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
    pub exec_bit, set_exec_bit: 14,8;
}

#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Addr64 {
    pub lo: u32,
    pub hi: u32,
}

/// Caliptra Authorization Manifest Image Metadata
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadata {
    pub fw_id: u32,
    pub component_id: u32,
    pub classification: u32,
    pub flags: u32, // ImageMetadataFlags(image_source, ignore_auth_check)
    pub image_load_address: Addr64,
    pub image_staging_address: Addr64,
    pub digest: [u8; 48],
}

impl Default for AuthManifestImageMetadata {
    fn default() -> Self {
        AuthManifestImageMetadata {
            fw_id: u32::MAX,
            component_id: u32::MAX,
            classification: 0,
            flags: 0,
            image_load_address: Addr64 { lo: 0, hi: 0 },
            image_staging_address: Addr64 { lo: 0, hi: 0 },
            digest: [0; 48],
        }
    }
}

/// Caliptra Authorization Manifest Image Metadata Collection
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestImageMetadataCollection {
    pub entry_count: u32,

    pub image_metadata_list: [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
}

impl zeroize::Zeroize for AuthManifestImageMetadataCollection {
    fn zeroize(&mut self) {
        self.as_mut_bytes().zeroize();
    }
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
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthorizationManifest {
    pub preamble: AuthManifestPreamble,

    pub image_metadata_col: AuthManifestImageMetadataCollection,
}

#[cfg(test)]
mod test {
    use crate::{
        AuthManifestPreamble, AUTH_MANIFEST_PREAMBLE_SIZE, VENDOR_EXT_AUTH_PK_HASH_LEN,
        VENDOR_EXT_ID_AUTH_PK_HASH, VENDOR_EXT_ID_END,
    };
    use zerocopy::IntoBytes;

    #[test]
    fn test_auth_preamble_size() {
        assert_eq!(
            AUTH_MANIFEST_PREAMBLE_SIZE,
            AuthManifestPreamble::default().as_bytes().len()
        );
    }

    // Writes a single TLV record (`id ‖ len ‖ value`) into a preamble's Vendor Ext.
    fn set_vendor_ext_record(p: &mut AuthManifestPreamble, id: u16, value: &[u8]) {
        let mut off = 0usize;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&id.to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&(value.len() as u16).to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + value.len()].copy_from_slice(value);
        off += value.len();
        p.vendor_ext_size = off as u32;
    }

    #[test]
    fn test_vendor_ext_auth_pk_hash_roundtrip() {
        let mut p = AuthManifestPreamble::default();
        // Absent by default.
        assert_eq!(p.vendor_ext_auth_pk_hash(), None);

        // A well-formed 0x0001 record round-trips.
        let hash = [0xABu8; VENDOR_EXT_AUTH_PK_HASH_LEN];
        set_vendor_ext_record(&mut p, VENDOR_EXT_ID_AUTH_PK_HASH, &hash);
        assert_eq!(p.vendor_ext_auth_pk_hash(), Some(hash));
    }

    #[test]
    fn test_vendor_ext_auth_pk_hash_wrong_len_rejected() {
        let mut p = AuthManifestPreamble::default();
        // 0x0001 with a non-48 length is rejected.
        set_vendor_ext_record(&mut p, VENDOR_EXT_ID_AUTH_PK_HASH, &[0u8; 32]);
        assert_eq!(p.vendor_ext_auth_pk_hash(), None);
    }

    #[test]
    fn test_vendor_ext_unknown_id_skipped() {
        let mut p = AuthManifestPreamble::default();
        // An unknown record (0x00FF) precedes the 0x0001 record; it must be skipped by length.
        let unknown = [0x11u8; 8];
        let hash = [0xCDu8; VENDOR_EXT_AUTH_PK_HASH_LEN];
        let mut off = 0usize;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&0x00FFu16.to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&(unknown.len() as u16).to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + unknown.len()].copy_from_slice(&unknown);
        off += unknown.len();
        p.vendor_ext.0[off..off + 2].copy_from_slice(&VENDOR_EXT_ID_AUTH_PK_HASH.to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&(hash.len() as u16).to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + hash.len()].copy_from_slice(&hash);
        off += hash.len();
        p.vendor_ext_size = off as u32;
        assert_eq!(p.vendor_ext_auth_pk_hash(), Some(hash));
    }

    #[test]
    fn test_vendor_ext_end_terminates() {
        let mut p = AuthManifestPreamble::default();
        // An END (0x0000) record before 0x0001 terminates the walk → not found.
        let mut off = 0usize;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&VENDOR_EXT_ID_END.to_le_bytes());
        off += 4; // id + len(=0)
        p.vendor_ext.0[off..off + 2].copy_from_slice(&VENDOR_EXT_ID_AUTH_PK_HASH.to_le_bytes());
        off += 2;
        p.vendor_ext.0[off..off + 2].copy_from_slice(&48u16.to_le_bytes());
        p.vendor_ext_size = (off + 2 + 48) as u32;
        assert_eq!(p.vendor_ext_auth_pk_hash(), None);
    }

    #[test]
    fn test_vendor_ext_inside_signed_range() {
        // The Vendor Ext field must fall inside the vendor-signed span so it is
        // authenticated by the existing vendor signature.
        let range = AuthManifestPreamble::vendor_signed_data_range();
        let ext_off = core::mem::offset_of!(AuthManifestPreamble, vendor_ext) as u32;
        let ext_end = ext_off + core::mem::size_of::<crate::AuthManifestVendorExt>() as u32;
        assert!(
            range.start <= ext_off && ext_end <= range.end,
            "vendor_ext [{ext_off}, {ext_end}) not within signed range [{}, {})",
            range.start,
            range.end
        );
    }
}
