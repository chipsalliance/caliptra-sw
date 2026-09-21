/*++

Licensed under the Apache-2.0 license.

File Name:

    get_image_info.rs

Abstract:

    File contains GET_IMAGE_INFO mailbox command.

--*/

use crate::Drivers;
use crate::{manifest::find_metadata_entry_by_type, mutrefbytes};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    AuthManifestSource, GetImageInfoFlags, GetImageInfoReq, GetImageInfoResp, MailboxRespHeader,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

pub struct GetImageInfoCmd;
impl GetImageInfoCmd {
    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if let Ok(cmd) = GetImageInfoReq::ref_from_bytes(cmd_args) {
            if cmd.flags & !GetImageInfoFlags::all().bits() != 0 {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }
            let persistent_data = drivers.persistent_data.get();
            let fw_id = u32::from_le_bytes(cmd.fw_id);
            let manifest_source = AuthManifestSource::from_flags(cmd.flags)
                .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
            let metadata = find_metadata_entry_by_type(
                &persistent_data.fw.auth_manifest_image_metadata_col,
                &persistent_data.fw.owner_auth_manifest_image_metadata_col,
                fw_id,
                manifest_source,
            )
            .ok_or(CaliptraError::RUNTIME_IMAGE_METADATA_NOT_FOUND)?;

            let resp = mutrefbytes::<GetImageInfoResp>(resp)?;
            resp.hdr = MailboxRespHeader::default();
            resp.component_id = metadata.component_id;
            resp.flags = metadata.flags;
            resp.image_load_address_high = metadata.image_load_address.hi;
            resp.image_load_address_low = metadata.image_load_address.lo;
            resp.image_staging_address_high = metadata.image_staging_address.hi;
            resp.image_staging_address_low = metadata.image_staging_address.lo;
            resp.digest = metadata.digest;
            Ok(core::mem::size_of::<GetImageInfoResp>())
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
