/*++

Licensed under the Apache-2.0 license.

File Name:

    get_image_info.rs

Abstract:

    File contains GET_IMAGE_INFO mailbox command.

--*/

use crate::Drivers;
use caliptra_auth_man_types::{AuthManifestImageMetadata, AuthManifestImageMetadataCollection};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    GetImageInfoReq, GetImageInfoResp, MailboxResp, MailboxRespHeader,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct GetImageInfoCmd;
impl GetImageInfoCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Ok(cmd) = GetImageInfoReq::ref_from_bytes(cmd_args) {
            let metadata = Self::get_image_metadata(drivers, cmd)?;

            Ok(MailboxResp::GetImageInfo(GetImageInfoResp {
                hdr: MailboxRespHeader::default(),
                component_id: metadata.component_id,
                flags: metadata.flags,
                image_load_address_high: metadata.image_load_address.hi,
                image_load_address_low: metadata.image_load_address.lo,
                image_staging_address_high: metadata.image_staging_address.hi,
                image_staging_address_low: metadata.image_staging_address.lo,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn get_image_metadata(
        drivers: &mut Drivers,
        cmd: &GetImageInfoReq,
    ) -> CaliptraResult<AuthManifestImageMetadata> {
        // Check if firmware id is present in the image metadata entry collection.
        let persistent_data = drivers.persistent_data.get();
        let auth_manifest_image_metadata_col = &persistent_data.auth_manifest_image_metadata_col;
        let cmd_fw_id = u32::from_le_bytes(cmd.fw_id);
        if let Some(metadata_entry) =
            Self::find_metadata_entry(auth_manifest_image_metadata_col, cmd_fw_id)
        {
            Ok(*metadata_entry)
        } else {
            Err(CaliptraError::RUNTIME_IMAGE_METADATA_NOT_FOUND)
        }
    }

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
    fn find_metadata_entry(
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
}
