/*++

Licensed under the Apache-2.0 license.

File Name:

    get_image_info.rs

Abstract:

    File contains GET_IMAGE_INFO mailbox command.

--*/

use crate::Drivers;
use crate::{manifest::find_metadata_entry, mutrefbytes};
use caliptra_auth_man_types::AuthManifestImageMetadata;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{GetImageInfoReq, GetImageInfoResp, MailboxRespHeader};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct GetImageInfoCmd;
impl GetImageInfoCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if let Ok(cmd) = GetImageInfoReq::ref_from_bytes(cmd_args) {
            let metadata = Self::get_image_metadata(drivers, cmd)?;

            let resp = mutrefbytes::<GetImageInfoResp>(resp)?;
            resp.hdr = MailboxRespHeader::default();
            resp.component_id = metadata.component_id;
            resp.flags = metadata.flags;
            resp.image_load_address_high = metadata.image_load_address.hi;
            resp.image_load_address_low = metadata.image_load_address.lo;
            resp.image_staging_address_high = metadata.image_staging_address.hi;
            resp.image_staging_address_low = metadata.image_staging_address.lo;
            Ok(core::mem::size_of::<GetImageInfoResp>())
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
            find_metadata_entry(auth_manifest_image_metadata_col, cmd_fw_id)
        {
            Ok(*metadata_entry)
        } else {
            Err(CaliptraError::RUNTIME_IMAGE_METADATA_NOT_FOUND)
        }
    }
}
