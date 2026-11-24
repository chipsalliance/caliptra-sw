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
use core::mem::{offset_of, size_of};
use core::ops::Range;
use memoffset::span_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

pub const AUTH_MANIFEST_MARKER: u32 = 0x324D_5441;
pub const AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT: usize = 80;
pub const AUTH_MANIFEST_PREAMBLE_SIZE: usize = 24292;

// The vendor-signed data is a single contiguous range only if the policy
// fields are immediately followed by `vendor_pub_keys`.
const _: () = assert!(
    AuthManifestPreamble::policy_fields_range().end
        == AuthManifestPreamble::vendor_pub_keys_range().start
);

// The vendor-signed data spans `version` through the end of `vendor_pub_keys`,
// ending exactly where `vendor_pub_keys_signatures` begins.
const _: () = {
    let range = AuthManifestPreamble::vendor_signed_data_range();
    assert!(range.start as usize == offset_of!(AuthManifestPreamble, version));
    assert!(range.end as usize == offset_of!(AuthManifestPreamble, vendor_pub_keys_signatures));
};
/// Firmware ID reserved for the optional UEID entry in the original SoC manifest.
pub const AUTH_MANIFEST_UEID_FW_ID: u32 = 0x0000_0FFF;
/// Number of bytes in a device UEID.
pub const AUTH_MANIFEST_UEID_LEN: usize = 17;

bitflags::bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct AuthManifestFlags : u32 {
        const VENDOR_SIGNATURE_REQUIRED = 0b1;
        const DEBUG_IMAGE = 0b10;
        /// Binds the preamble to one device. When set, the vendor and owner
        /// preamble signatures also cover the 17-byte device UEID (appended
        /// after the public keys), and the IMC must contain the device UEID
        /// entry (`AUTH_MANIFEST_UEID_FW_ID`). Requires `VENDOR_SIGNATURE_REQUIRED`.
        const UEID_BOUND_PREAMBLE = 0b100;
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

/// Caliptra Authorization Image Manifest Preamble
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct AuthManifestPreamble {
    pub marker: u32,

    pub size: u32,

    pub version: u32,

    pub svn: u32,

    pub flags: u32, // AuthManifestFlags(VENDOR_SIGNATURE_REQUIRED, DEBUG_IMAGE)

    pub vendor_pub_keys: AuthManifestPubKeys,

    pub vendor_pub_keys_signatures: AuthManifestSignatures,

    pub owner_pub_keys: AuthManifestPubKeys,

    pub owner_pub_keys_signatures: AuthManifestSignatures,

    pub vendor_image_metdata_signatures: AuthManifestSignatures,

    pub owner_image_metdata_signatures: AuthManifestSignatures,
}

impl AuthManifestPreamble {
    /// Returns `Range<u32>` containing the version, svn and flags.
    ///
    /// These policy fields are covered by both the vendor and owner
    /// preamble signatures.
    pub const fn policy_fields_range() -> Range<u32> {
        let start = offset_of!(AuthManifestPreamble, version);
        let end = offset_of!(AuthManifestPreamble, flags) + size_of::<u32>();
        start as u32..end as u32
    }

    /// Returns `Range<u32>` containing the vendor_pub_keys
    pub const fn vendor_pub_keys_range() -> Range<u32> {
        let start = offset_of!(AuthManifestPreamble, vendor_pub_keys);
        start as u32..(start + size_of::<AuthManifestPubKeys>()) as u32
    }

    /// Returns `Range<u32>` signed by `vendor_pub_keys_signatures`: the policy
    /// fields (`version..=flags`) followed by `vendor_pub_keys`.
    ///
    /// The two are adjacent in the preamble (checked at build time), so the
    /// vendor-signed message is a single contiguous range.
    pub const fn vendor_signed_data_range() -> Range<u32> {
        Self::policy_fields_range().start..Self::vendor_pub_keys_range().end
    }

    /// Returns `Range<u32>` containing the vendor_pub_keys_signatures
    pub fn vendor_pub_keys_signatures_range() -> Range<u32> {
        let span = span_of!(AuthManifestPreamble, vendor_pub_keys_signatures);
        span.start as u32..span.end as u32
    }

    /// Returns `Range<u32>` containing the owner_pub_keys
    pub const fn owner_pub_keys_range() -> Range<u32> {
        let start = offset_of!(AuthManifestPreamble, owner_pub_keys);
        start as u32..(start + size_of::<AuthManifestPubKeys>()) as u32
    }

    /// Returns the preamble ranges signed by `owner_pub_keys_signatures`.
    ///
    /// The owner-signed message is the concatenation, in order, of the
    /// policy fields (`version..=flags`) and `owner_pub_keys`. The vendor
    /// public keys and signatures are not covered.
    pub const fn owner_signed_data_ranges() -> [Range<u32>; 2] {
        [Self::policy_fields_range(), Self::owner_pub_keys_range()]
    }

    /// Returns, in order, the chunks of the message signed by
    /// `vendor_pub_keys_signatures`: `version`, `svn`, `flags`,
    /// `vendor_pub_keys`, then the device UEID (only if
    /// `UEID_BOUND_PREAMBLE`).
    ///
    /// With `ueid == None` the concatenation equals
    /// [`Self::vendor_signed_data_range`].
    pub fn vendor_signed_data_chunks<'a>(
        &'a self,
        ueid: Option<&'a [u8; AUTH_MANIFEST_UEID_LEN]>,
    ) -> impl Iterator<Item = &'a [u8]> + Clone + 'a {
        self.signed_data_chunks(ueid, self.vendor_pub_keys.as_bytes())
    }

    /// Returns, in order, the chunks of the message signed by
    /// `owner_pub_keys_signatures`: `version`, `svn`, `flags`,
    /// `owner_pub_keys`, then the device UEID (only if
    /// `UEID_BOUND_PREAMBLE`).
    ///
    /// With `ueid == None` the concatenation equals
    /// [`Self::owner_signed_data_ranges`].
    pub fn owner_signed_data_chunks<'a>(
        &'a self,
        ueid: Option<&'a [u8; AUTH_MANIFEST_UEID_LEN]>,
    ) -> impl Iterator<Item = &'a [u8]> + Clone + 'a {
        self.signed_data_chunks(ueid, self.owner_pub_keys.as_bytes())
    }

    fn signed_data_chunks<'a>(
        &'a self,
        ueid: Option<&'a [u8; AUTH_MANIFEST_UEID_LEN]>,
        pub_keys: &'a [u8],
    ) -> impl Iterator<Item = &'a [u8]> + Clone + 'a {
        [
            self.version.as_bytes(),
            self.svn.as_bytes(),
            self.flags.as_bytes(),
            pub_keys,
        ]
        .into_iter()
        .chain(ueid.map(|ueid| ueid.as_slice()))
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
    pub dma_single_dword_read, set_dma_single_dword_read: 3;
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
    pub flags: u32, // ImageMetadataFlags
    pub image_load_address: Addr64,
    pub image_staging_address: Addr64,
    pub digest: [u8; 48],
}

impl AuthManifestImageMetadata {
    /// Creates a canonical UEID metadata entry with zero-padded digest bytes.
    pub fn new_ueid(ueid: &[u8; AUTH_MANIFEST_UEID_LEN]) -> Self {
        let mut digest = [0; 48];
        digest[..AUTH_MANIFEST_UEID_LEN].copy_from_slice(ueid);
        Self {
            fw_id: AUTH_MANIFEST_UEID_FW_ID,
            digest,
            ..Default::default()
        }
    }

    /// Returns the UEID if this is a UEID entry (`AUTH_MANIFEST_UEID_FW_ID`).
    pub fn ueid(&self) -> Option<[u8; AUTH_MANIFEST_UEID_LEN]> {
        if self.fw_id != AUTH_MANIFEST_UEID_FW_ID {
            return None;
        }
        self.digest[..AUTH_MANIFEST_UEID_LEN].try_into().ok()
    }
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

// =====================================================================
// Owner Authorization Manifest
//
// A separate, owner-only manifest format. Carries owner public keys and
// owner signatures only; no vendor key or signature fields. Loaded via
// the dedicated `SET_OWNER_AUTH_MANIFEST` mailbox command into a
// dedicated owner-only Image Metadata Entry collection (separate from
// the existing vendor + owner collection populated by
// `SET_AUTH_MANIFEST`).
// =====================================================================

/// Magic marker identifying an Owner Authorization Manifest. ASCII "OWOM".
pub const OWNER_AUTH_MANIFEST_MARKER: u32 = 0x4D4F_574F;

/// Maximum number of Image Metadata Entries in the owner-only IMC.
/// Sized smaller than the vendor + owner cap because owner-only
/// manifests are expected to carry on the order of ~16 entries (per
/// the RFC use case); the cap leaves headroom while keeping the
/// owner-only DCCM region small.
pub const OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT: usize = 32;

/// Serialized size of [`OwnerAuthManifestPreamble`] in bytes.
/// Validated by the unit test below.
pub const OWNER_AUTH_MANIFEST_PREAMBLE_SIZE: usize = 12156;

/// Serialized size of [`OwnerAuthorizationManifest`] in bytes.
/// Validated by the unit test below.
pub const OWNER_AUTH_MANIFEST_SIZE: usize = 14720;

/// Preamble of the Owner Authorization Manifest.
///
/// Contains the owner ECC and PQC public keys, the owner endorsement
/// signatures over the Preamble policy fields, and the owner signatures
/// over the IMC.
///
/// Signature coverage:
/// - `owner_pub_keys_signatures` covers the Preamble policy fields
///   (`version`, `svn`, `flags`, `owner_pub_keys`). The marker and
///   Preamble size are validated separately.
/// - `owner_image_metdata_signatures` covers the serialized
///   [`OwnerAuthManifestImageMetadataCollection`] (entry count + IMEs).
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OwnerAuthManifestPreamble {
    pub marker: u32,

    pub size: u32,

    pub version: u32,

    pub svn: u32,

    pub flags: u32,

    pub owner_pub_keys: AuthManifestPubKeys,

    pub owner_pub_keys_signatures: AuthManifestSignatures,

    pub owner_image_metdata_signatures: AuthManifestSignatures,
}

impl OwnerAuthManifestPreamble {
    /// Range covering the Preamble policy fields signed by
    /// `owner_pub_keys_signatures`.
    pub fn owner_signed_data_range() -> Range<u32> {
        let span = span_of!(OwnerAuthManifestPreamble, version..=owner_pub_keys);
        span.start as u32..span.end as u32
    }

    /// Range covering `owner_pub_keys_signatures`.
    pub fn owner_pub_keys_signatures_range() -> Range<u32> {
        let span = span_of!(OwnerAuthManifestPreamble, owner_pub_keys_signatures);
        span.start as u32..span.end as u32
    }

    /// Range covering `owner_image_metdata_signatures`.
    pub fn owner_image_metdata_signatures_range() -> Range<u32> {
        let span = span_of!(OwnerAuthManifestPreamble, owner_image_metdata_signatures);
        span.start as u32..span.end as u32
    }
}

/// Owner-only Image Metadata Collection.
///
/// Per-entry layout is identical to the existing
/// [`AuthManifestImageMetadata`] used by the vendor + owner manifest.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OwnerAuthManifestImageMetadataCollection {
    pub entry_count: u32,

    pub image_metadata_list:
        [AuthManifestImageMetadata; OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
}

impl zeroize::Zeroize for OwnerAuthManifestImageMetadataCollection {
    fn zeroize(&mut self) {
        self.as_mut_bytes().zeroize();
    }
}

impl Default for OwnerAuthManifestImageMetadataCollection {
    fn default() -> Self {
        OwnerAuthManifestImageMetadataCollection {
            entry_count: 0,
            image_metadata_list: [AuthManifestImageMetadata::default();
                OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT],
        }
    }
}

/// Caliptra Owner Authorization Manifest.
///
/// Loaded via the `SET_OWNER_AUTH_MANIFEST` mailbox command. Carries
/// owner-only authorization material; never mixed with the vendor +
/// owner collection populated by `SET_AUTH_MANIFEST`.
#[repr(C)]
#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, Clone, Copy, Debug, Zeroize, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OwnerAuthorizationManifest {
    pub preamble: OwnerAuthManifestPreamble,

    pub image_metadata_col: OwnerAuthManifestImageMetadataCollection,
}

#[cfg(test)]
mod test {
    extern crate std;
    use std::vec::Vec;

    use crate::{
        AuthManifestImageMetadata, AuthManifestPreamble, ImageMetadataFlags,
        OwnerAuthManifestPreamble, OwnerAuthorizationManifest, AUTH_MANIFEST_PREAMBLE_SIZE,
        AUTH_MANIFEST_UEID_FW_ID, AUTH_MANIFEST_UEID_LEN, OWNER_AUTH_MANIFEST_MARKER,
        OWNER_AUTH_MANIFEST_PREAMBLE_SIZE, OWNER_AUTH_MANIFEST_SIZE,
    };
    use zerocopy::IntoBytes;

    #[test]
    fn test_ueid_metadata_encoding() {
        let ueid = [0xA5; AUTH_MANIFEST_UEID_LEN];
        let metadata = AuthManifestImageMetadata::new_ueid(&ueid);

        assert_eq!(AUTH_MANIFEST_UEID_FW_ID, 0x0000_0FFF);
        assert_eq!(metadata.fw_id, AUTH_MANIFEST_UEID_FW_ID);
        assert_eq!(&metadata.digest[..AUTH_MANIFEST_UEID_LEN], &ueid);
        assert_eq!(
            &metadata.digest[AUTH_MANIFEST_UEID_LEN..],
            &[0; 48 - AUTH_MANIFEST_UEID_LEN]
        );
        assert_eq!(metadata.ueid(), Some(ueid));
        assert_eq!(AuthManifestImageMetadata::default().ueid(), None);
    }

    #[test]
    fn test_dma_single_dword_read_flag_encoding() {
        let mut flags = ImageMetadataFlags(0);
        flags.set_dma_single_dword_read(true);

        assert!(flags.dma_single_dword_read());
        assert_eq!(flags.0, 1 << 3);
    }

    #[test]
    fn test_auth_preamble_size() {
        assert_eq!(
            AUTH_MANIFEST_PREAMBLE_SIZE,
            AuthManifestPreamble::default().as_bytes().len()
        );
    }

    #[test]
    fn test_owner_auth_preamble_size() {
        assert_eq!(
            OWNER_AUTH_MANIFEST_PREAMBLE_SIZE,
            OwnerAuthManifestPreamble::default().as_bytes().len()
        );
    }

    #[test]
    fn test_owner_auth_manifest_size() {
        assert_eq!(
            OWNER_AUTH_MANIFEST_SIZE,
            OwnerAuthorizationManifest::default().as_bytes().len()
        );
    }

    #[test]
    fn test_owner_auth_manifest_marker_value() {
        // 'O','W','O','M' little-endian.
        assert_eq!(OWNER_AUTH_MANIFEST_MARKER, 0x4D4F_574F);
        assert_eq!(&OWNER_AUTH_MANIFEST_MARKER.to_le_bytes(), b"OWOM");
    }

    #[test]
    fn test_owner_signed_data_range_covers_policy_fields() {
        let range = OwnerAuthManifestPreamble::owner_signed_data_range();
        // The signed range must start at `version` (i.e. skip
        // `marker` and `size` which are validated by exact equality)
        // and end at the end of `owner_pub_keys`. It must not include
        // either signature region.
        let pub_keys_sigs = OwnerAuthManifestPreamble::owner_pub_keys_signatures_range();
        let imc_sigs = OwnerAuthManifestPreamble::owner_image_metdata_signatures_range();
        assert!(range.end <= pub_keys_sigs.start);
        assert!(pub_keys_sigs.end <= imc_sigs.start);
        // Non-empty.
        assert!(range.start < range.end);
    }

    #[test]
    fn test_auth_manifest_owner_signed_data() {
        let [policy, owner] = AuthManifestPreamble::owner_signed_data_ranges();
        assert_eq!(owner, AuthManifestPreamble::owner_pub_keys_range());
        // Starts at `version` (skips marker and size) and stops before
        // the vendor public keys; vendor keys and signatures are not covered.
        let vendor = AuthManifestPreamble::vendor_signed_data_range();
        assert_eq!(policy.start, vendor.start);
        assert_eq!(policy.len(), 3 * core::mem::size_of::<u32>());
        // Vendor and owner sign the same policy fields.
        let vendor_pub_keys = AuthManifestPreamble::vendor_pub_keys_range();
        assert_eq!(policy.end, vendor_pub_keys.start);
        assert_eq!(vendor.end, vendor_pub_keys.end);
        let vendor_sigs = AuthManifestPreamble::vendor_pub_keys_signatures_range();
        assert_eq!(vendor_sigs.end, owner.start);
    }

    fn patterned_preamble() -> AuthManifestPreamble {
        let mut preamble = AuthManifestPreamble::default();
        preamble
            .as_mut_bytes()
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = i as u8);
        preamble
    }

    fn concat<'a>(chunks: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
        chunks.flatten().copied().collect()
    }

    #[test]
    fn test_signed_data_chunks_without_ueid_match_ranges() {
        let preamble = patterned_preamble();
        let bytes = preamble.as_bytes();

        assert_eq!(preamble.vendor_signed_data_chunks(None).count(), 4);
        let vendor = concat(preamble.vendor_signed_data_chunks(None));
        let range = AuthManifestPreamble::vendor_signed_data_range();
        assert_eq!(vendor, &bytes[range.start as usize..range.end as usize]);

        assert_eq!(preamble.owner_signed_data_chunks(None).count(), 4);
        let owner = concat(preamble.owner_signed_data_chunks(None));
        let expected = concat(
            AuthManifestPreamble::owner_signed_data_ranges()
                .into_iter()
                .map(|r| &bytes[r.start as usize..r.end as usize]),
        );
        assert_eq!(owner, expected);
    }

    #[test]
    fn test_signed_data_chunks_with_ueid() {
        let preamble = patterned_preamble();
        let bytes = preamble.as_bytes();
        let ueid = [0xA5; AUTH_MANIFEST_UEID_LEN];
        let policy = AuthManifestPreamble::policy_fields_range();
        let policy = &bytes[policy.start as usize..policy.end as usize];

        let vendor_keys = AuthManifestPreamble::vendor_pub_keys_range();
        let expected = [
            policy,
            &bytes[vendor_keys.start as usize..vendor_keys.end as usize],
            &ueid,
        ]
        .concat();
        assert_eq!(preamble.vendor_signed_data_chunks(Some(&ueid)).count(), 5);
        assert_eq!(
            concat(preamble.vendor_signed_data_chunks(Some(&ueid))),
            expected
        );

        let owner_keys = AuthManifestPreamble::owner_pub_keys_range();
        let expected = [
            policy,
            &bytes[owner_keys.start as usize..owner_keys.end as usize],
            &ueid,
        ]
        .concat();
        assert_eq!(preamble.owner_signed_data_chunks(Some(&ueid)).count(), 5);
        assert_eq!(
            concat(preamble.owner_signed_data_chunks(Some(&ueid))),
            expected
        );
    }
}
