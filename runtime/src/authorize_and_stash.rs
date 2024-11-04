/*++

Licensed under the Apache-2.0 license.

File Name:

    authorize_and_stash.rs

Abstract:

    File contains AUTHORIZE_AND_STASH mailbox command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers, StashMeasurementCmd};
use caliptra_auth_man_types::{
    AuthManifestImageMetadataCollection, AuthManifestImageMetadataCollectionHeader,
    AuthManifestPreamble, AUTH_MANIFEST_MARKER,
};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::mailbox_api::{
    AuthAndStashFlags, AuthorizeAndStashReq, AuthorizeAndStashResp, ImageHashSource, MailboxResp,
    MailboxRespHeader, SetAuthManifestReq,
};
use caliptra_drivers::{
    pcr_log::PCR_ID_STASH_MEASUREMENT, Array4x12, Array4xN, AuthManifestImageMetadataList,
    CaliptraError, CaliptraResult, Ecc384, Ecc384PubKey, Ecc384Signature, HashValue, Lms,
    PersistentData, RomVerifyConfig, Sha256, Sha384, SocIfc,
    AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT,
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
use zerocopy::{AsBytes, FromBytes};

pub const AUTHORIZE_IMAGE: u32 = 0xDEADC0DE;
pub const DENY_IMAGE_AUTHORIZATION: u32 = 0x21523F21;

pub struct AuthorizeAndStashCmd;
impl AuthorizeAndStashCmd {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        if let Some(cmd) = AuthorizeAndStashReq::read_from(cmd_args) {
            if ImageHashSource::from(cmd.source) != ImageHashSource::InRequest {
                Err(CaliptraError::RUNTIME_AUTH_AND_STASH_UNSUPPORTED_IMAGE_SOURCE)?;
            }

            // Check if image hash is present in the image metadata entry collection.
            let persistent_data = drivers.persistent_data.get();
            let auth_manifest_image_metadata_col =
                &persistent_data.auth_manifest_image_metadata_col;

            let mut auth_result = DENY_IMAGE_AUTHORIZATION;
            for metadata_entry in auth_manifest_image_metadata_col.image_metadata_list.iter() {
                if cfi_launder(metadata_entry.digest) == cmd.measurement {
                    caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                        &Array4x12::from(metadata_entry.digest).0,
                        &Array4x12::from(cmd.measurement).0,
                    );
                    auth_result = AUTHORIZE_IMAGE;
                    break;
                }
            }

            // Stash the measurement if the image is authorized.
            if auth_result == AUTHORIZE_IMAGE {
                let flags: AuthAndStashFlags = cmd.flags.into();
                if !flags.contains(AuthAndStashFlags::SKIP_STASH) {
                    let dpe_result = StashMeasurementCmd::stash_measurement(
                        drivers,
                        &cmd.metadata,
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
}
