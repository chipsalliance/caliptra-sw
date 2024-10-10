/*++

Licensed under the Apache-2.0 license.

File Name:

    authorize_and_stash.rs

Abstract:

    File contains AUTHORIZE_AND_STASH mailbox command.

--*/

use core::cmp::{self, min};
use core::mem::size_of;

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers, StashMeasurementCmd};
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection, AuthManifestPreamble,
    ImageMetadataFlags, AUTH_MANIFEST_MARKER,
};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::{cfi_assert, cfi_assert_eq, cfi_launder};
use caliptra_common::mailbox_api::{
    AuthAndStashFlags, AuthorizeAndStashReq, AuthorizeAndStashResp, ImageHashSource, MailboxResp,
    MailboxRespHeader, SetAuthManifestReq,
};
use caliptra_drivers::{
    pcr_log::PCR_ID_STASH_MEASUREMENT, Array4x12, Array4xN, AuthManifestImageMetadataList,
    CaliptraError, CaliptraResult, Ecc384, Ecc384PubKey, Ecc384Signature, HashValue, Lms,
    PersistentData, RomVerifyConfig, Sha256, Sha384, SocIfc,
};
use caliptra_image_types::{
    ImageDigest, ImageEccPubKey, ImageEccSignature, ImageLmsPublicKey, ImageLmsSignature,
    ImagePreamble, SHA192_DIGEST_WORD_SIZE, SHA384_DIGEST_BYTE_SIZE,
};
use crypto::{AlgLen, Crypto};
use dpe::{
    commands::{CommandExecution, DeriveContextCmd, DeriveContextFlags},
    context::ContextHandle,
    dpe_instance::DpeEnv,
    response::DpeErrorCode,
};
use memoffset::offset_of;
use zerocopy::{FromBytes, IntoBytes};

pub const IMAGE_AUTHORIZED: u32 = 0xDEADC0DE; // Either FW ID and image digest matched or 'ignore_auth_check' is set for the FW ID.
pub const IMAGE_NOT_AUTHORIZED: u32 = 0x21523F21; // FW ID not found in the image metadata entry collection.
pub const IMAGE_HASH_MISMATCH: u32 = 0x8BFB95CB; // FW ID matched, but image digest mismatched.

pub struct AuthorizeAndStashCmd;
impl AuthorizeAndStashCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Ok(cmd) = AuthorizeAndStashReq::ref_from_bytes(cmd_args) {
            if ImageHashSource::from(cmd.source) != ImageHashSource::InRequest {
                Err(CaliptraError::RUNTIME_AUTH_AND_STASH_UNSUPPORTED_IMAGE_SOURCE)?;
            }

            // Check if firmware id is present in the image metadata entry collection.
            let persistent_data = drivers.persistent_data.get();
            let auth_manifest_image_metadata_col =
                &persistent_data.auth_manifest_image_metadata_col;

            let cmd_fw_id = u32::from_le_bytes(cmd.fw_id);
            let auth_result = if let Some(metadata_entry) =
                Self::find_metadata_entry(auth_manifest_image_metadata_col, cmd_fw_id)
            {
                // If 'ignore_auth_check' is set, then skip the image digest comparison and authorize the image.
                let flags = ImageMetadataFlags(metadata_entry.flags);
                if flags.ignore_auth_check() {
                    cfi_assert!(cfi_launder(flags.ignore_auth_check()));
                    IMAGE_AUTHORIZED
                } else if cfi_launder(metadata_entry.digest) == cmd.measurement {
                    caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                        &Array4x12::from(metadata_entry.digest).0,
                        &Array4x12::from(cmd.measurement).0,
                    );
                    IMAGE_AUTHORIZED
                } else {
                    IMAGE_HASH_MISMATCH
                }
            } else {
                IMAGE_NOT_AUTHORIZED
            };

            // Stash the measurement if the image is authorized.
            if auth_result == IMAGE_AUTHORIZED {
                let flags: AuthAndStashFlags = cmd.flags.into();
                if !flags.contains(AuthAndStashFlags::SKIP_STASH) {
                    let dpe_result = StashMeasurementCmd::stash_measurement(
                        drivers,
                        &cmd.fw_id,
                        &cmd.measurement,
                    )?;
                    if dpe_result != DpeErrorCode::NoError {
                        drivers
                            .soc_ifc
                            .set_fw_extended_error(dpe_result.get_error_code());
                        Err(CaliptraError::RUNTIME_AUTH_AND_STASH_MEASUREMENT_DPE_ERROR)?;
                    }
                }
            }

            Ok(MailboxResp::AuthorizeAndStash(AuthorizeAndStashResp {
                hdr: MailboxRespHeader::default(),
                auth_req_result: auth_result,
            }))
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
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
            .map(|index| &auth_manifest_image_metadata_col.image_metadata_list[index])
    }
}
