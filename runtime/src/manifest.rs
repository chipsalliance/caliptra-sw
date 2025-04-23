/*++

Licensed under the Apache-2.0 license.

File Name:

    manifest.rs

Abstract:

    File contains utilities related to the auth manifest.

--*/

use caliptra_auth_man_types::{AuthManifestImageMetadata, AuthManifestImageMetadataCollection};

/// Search for a metadata entry in the sorted `AuthManifestImageMetadataCollection` that matches the firmware ID.
///
/// This function performs a binary search on the `image_metadata_list` of the provided `AuthManifestImageMetadataCollection`.
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
    auth_manifest_image_metadata_col
        .image_metadata_list
        .binary_search_by(|metadata| metadata.fw_id.cmp(&cmd_fw_id))
        .ok()
        .map(|index| {
            auth_manifest_image_metadata_col
                .image_metadata_list
                .get(index)
        })?
}
