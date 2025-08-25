/*++

Licensed under the Apache-2.0 license.

File Name:

    authorize_and_stash.rs

Abstract:

    File contains AUTHORIZE_AND_STASH mailbox command.

--*/

use crate::manifest::find_metadata_entry;
use crate::{mutrefbytes, Drivers, StashMeasurementCmd};
use caliptra_auth_man_types::ImageMetadataFlags;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::mailbox_api::{
    AuthAndStashFlags, AuthorizeAndStashReq, AuthorizeAndStashResp, ImageHashSource,
    MailboxRespHeader,
};
use caliptra_drivers::{AesDmaMode, DmaRecovery};
use caliptra_drivers::{Array4x12, AxiAddr, CaliptraError, CaliptraResult};
use dpe::response::DpeErrorCode;
use zerocopy::FromBytes;

pub const IMAGE_AUTHORIZED: u32 = 0xDEADC0DE; // Either FW ID and image digest matched or 'ignore_auth_check' is set for the FW ID.
pub const IMAGE_NOT_AUTHORIZED: u32 = 0x21523F21; // FW ID not found in the image metadata entry collection.
pub const IMAGE_HASH_MISMATCH: u32 = 0x8BFB95CB; // FW ID matched, but image digest mismatched.

pub struct AuthorizeAndStashCmd;
impl AuthorizeAndStashCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(
        drivers: &mut Drivers,
        cmd_args: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if let Ok(cmd) = AuthorizeAndStashReq::ref_from_bytes(cmd_args) {
            let resp = mutrefbytes::<AuthorizeAndStashResp>(resp)?;
            resp.hdr = MailboxRespHeader::default();
            resp.auth_req_result = Self::authorize_and_stash(drivers, cmd)?;
            Ok(core::mem::size_of::<AuthorizeAndStashResp>())
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn authorize_and_stash(
        drivers: &mut Drivers,
        cmd: &AuthorizeAndStashReq,
    ) -> CaliptraResult<u32> {
        let source = ImageHashSource::from(cmd.source);
        if source == ImageHashSource::Invalid {
            Err(CaliptraError::RUNTIME_AUTH_AND_STASH_UNSUPPORTED_IMAGE_SOURCE)?;
        }
        // Check if firmware id is present in the image metadata entry collection.
        let persistent_data = drivers.persistent_data.get();
        let dma_image = DmaRecovery::new(
            drivers.soc_ifc.recovery_interface_base_addr().into(),
            drivers.soc_ifc.caliptra_base_axi_addr().into(),
            drivers.soc_ifc.mci_base_addr().into(),
            &drivers.dma,
        );
        let auth_manifest_image_metadata_col = &persistent_data.auth_manifest_image_metadata_col;

        let cmd_fw_id = u32::from_le_bytes(cmd.fw_id);
        let auth_result = if let Some(metadata_entry) =
            find_metadata_entry(auth_manifest_image_metadata_col, cmd_fw_id)
        {
            // If 'ignore_auth_check' is set, then skip the image digest comparison and authorize the image.
            let flags = ImageMetadataFlags(metadata_entry.flags);
            if flags.ignore_auth_check() {
                cfi_assert!(cfi_launder(flags.ignore_auth_check()));
                IMAGE_AUTHORIZED
            } else if source == ImageHashSource::InRequest {
                if cfi_launder(metadata_entry.digest) == cmd.measurement {
                    caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                        &Array4x12::from(metadata_entry.digest).0,
                        &Array4x12::from(cmd.measurement).0,
                    );
                    IMAGE_AUTHORIZED
                } else {
                    IMAGE_HASH_MISMATCH
                }
            } else if source == ImageHashSource::LoadAddress
                || source == ImageHashSource::StagingAddress
            {
                let image_source = if source == ImageHashSource::LoadAddress {
                    metadata_entry.image_load_address
                } else {
                    metadata_entry.image_staging_address
                };

                let measurement: [u8; 48] = dma_image
                    .sha384_image(
                        &mut drivers.sha2_512_384_acc,
                        AxiAddr {
                            hi: image_source.hi,
                            lo: image_source.lo,
                        },
                        cmd.image_size,
                        AesDmaMode::None,
                    )
                    .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?
                    .into();
                if cfi_launder(metadata_entry.digest) == measurement {
                    caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                        &Array4x12::from(metadata_entry.digest).0,
                        &Array4x12::from(measurement).0,
                    );
                    IMAGE_AUTHORIZED
                } else {
                    IMAGE_HASH_MISMATCH
                }
            } else {
                IMAGE_NOT_AUTHORIZED
            }
        } else {
            IMAGE_NOT_AUTHORIZED
        };
        // Stash the measurement if the image is authorized.
        if auth_result == IMAGE_AUTHORIZED {
            let flags: AuthAndStashFlags = cmd.flags.into();
            if !flags.contains(AuthAndStashFlags::SKIP_STASH) {
                let dpe_result =
                    StashMeasurementCmd::stash_measurement(drivers, &cmd.fw_id, &cmd.measurement)?;
                if dpe_result != DpeErrorCode::NoError {
                    drivers
                        .soc_ifc
                        .set_fw_extended_error(dpe_result.get_error_code());

                    Err(CaliptraError::RUNTIME_AUTH_AND_STASH_MEASUREMENT_DPE_ERROR)?;
                }
            }
        }

        Ok(auth_result)
    }
}
