/*++

Licensed under the Apache-2.0 license.

File Name:

    manifest.rs

Abstract:

    File contains utilities related to the auth manifest.

--*/

use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection,
    OwnerAuthManifestImageMetadataCollection,
};

/// Search for an active metadata entry in the sorted `AuthManifestImageMetadataCollection` that matches the firmware ID.
///
/// This function performs a binary search on the active entries in the `image_metadata_list` of the provided `AuthManifestImageMetadataCollection`.
/// It compares the firmware ID (`fw_id`) of each metadata entry with the provided `cmd_fw_id`.
///
/// # Arguments
///
/// * `auth_manifest_image_metadata_col` - A reference to the `AuthManifestImageMetadataCollection` containing the metadata entries.
/// * `cmd_fw_id` - The firmware ID from the command to search for.
///
/// # Returns
///
/// * `Option<&AuthManifestImageMetadata>` - Returns `Some(&AuthManifestImageMetadata)` if a matching entry is found,
///   otherwise returns `None`.
///
#[inline(never)]
pub fn find_metadata_entry(
    auth_manifest_image_metadata_col: &AuthManifestImageMetadataCollection,
    cmd_fw_id: u32,
) -> Option<&AuthManifestImageMetadata> {
    let image_metadata_list = auth_manifest_image_metadata_col
        .image_metadata_list
        .get(..auth_manifest_image_metadata_col.entry_count as usize)?;

    image_metadata_list
        .binary_search_by(|metadata| metadata.fw_id.cmp(&cmd_fw_id))
        .ok()
        .and_then(|index| image_metadata_list.get(index))
}

/// Search for a metadata entry in the sorted owner-only
/// `OwnerAuthManifestImageMetadataCollection` that matches the
/// firmware ID. Mirrors [`find_metadata_entry`] but operates on the
/// owner-only IMC populated by `SET_OWNER_AUTH_MANIFEST`.
///
/// Restricted to the `entry_count` prefix to avoid matching
/// zero-initialized tail entries (the owner-only collection uses a
/// distinct lookup path so this stricter behavior cannot regress
/// callers of the legacy [`find_metadata_entry`]).
#[inline(never)]
pub fn find_owner_metadata_entry(
    owner_auth_manifest_image_metadata_col: &OwnerAuthManifestImageMetadataCollection,
    cmd_fw_id: u32,
) -> Option<&AuthManifestImageMetadata> {
    let count = owner_auth_manifest_image_metadata_col.entry_count as usize;
    let list = owner_auth_manifest_image_metadata_col
        .image_metadata_list
        .get(..count)?;
    list.binary_search_by(|metadata| metadata.fw_id.cmp(&cmd_fw_id))
        .ok()
        .map(|index| &list[index])
}

#[cfg(test)]
mod test {
    use super::*;

    fn entry(fw_id: u32) -> AuthManifestImageMetadata {
        AuthManifestImageMetadata {
            fw_id,
            ..Default::default()
        }
    }

    #[test]
    fn find_owner_metadata_entry_hit_and_miss() {
        let mut col = OwnerAuthManifestImageMetadataCollection {
            entry_count: 3,
            ..Default::default()
        };
        col.image_metadata_list[0] = entry(2);
        col.image_metadata_list[1] = entry(5);
        col.image_metadata_list[2] = entry(9);
        // populated entries
        assert_eq!(find_owner_metadata_entry(&col, 2).unwrap().fw_id, 2);
        assert_eq!(find_owner_metadata_entry(&col, 5).unwrap().fw_id, 5);
        assert_eq!(find_owner_metadata_entry(&col, 9).unwrap().fw_id, 9);
        // miss
        assert!(find_owner_metadata_entry(&col, 7).is_none());
    }

    #[test]
    fn find_owner_metadata_entry_ignores_tail_zero_entries() {
        // entry_count=1 means the tail (all-zero `fw_id == 0`) must
        // not be matched even though the search key is 0.
        let mut col = OwnerAuthManifestImageMetadataCollection {
            entry_count: 1,
            ..Default::default()
        };
        col.image_metadata_list[0] = entry(42);
        assert!(find_owner_metadata_entry(&col, 0).is_none());
        assert_eq!(find_owner_metadata_entry(&col, 42).unwrap().fw_id, 42);
    }

    #[test]
    fn find_owner_metadata_entry_empty_collection() {
        let col = OwnerAuthManifestImageMetadataCollection::default();
        assert!(find_owner_metadata_entry(&col, 0).is_none());
        assert!(find_owner_metadata_entry(&col, 100).is_none());
    }
}
