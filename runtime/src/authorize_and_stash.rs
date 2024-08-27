/*++

Licensed under the Apache-2.0 license.

File Name:

    authorize_and_stash.rs

Abstract:

    File contains AUTHORIZE_AND_STASH mailbox command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_auth_man_types::AuthManifestImageMetadataCollection;
use caliptra_auth_man_types::AuthManifestImageMetadataCollectionHeader;
use caliptra_auth_man_types::AuthManifestPreamble;
use caliptra_auth_man_types::AUTH_MANIFEST_MARKER;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::mailbox_api::AuthAndStashFlags;
use caliptra_common::mailbox_api::ImageHashSource;
use caliptra_common::mailbox_api::SetAuthManifestReq;
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, MailboxResp, MailboxRespHeader,
};
use caliptra_drivers::Array4x12;
use caliptra_drivers::Array4xN;
use caliptra_drivers::AuthManifestImageMetadataList;
use caliptra_drivers::Ecc384;
use caliptra_drivers::Ecc384PubKey;
use caliptra_drivers::Ecc384Signature;
use caliptra_drivers::HashValue;
use caliptra_drivers::Lms;
use caliptra_drivers::PersistentData;
use caliptra_drivers::RomVerifyConfig;
use caliptra_drivers::Sha256;
use caliptra_drivers::Sha384;
use caliptra_drivers::SocIfc;
use caliptra_drivers::AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT;
use caliptra_drivers::{pcr_log::PCR_ID_STASH_MEASUREMENT, CaliptraError, CaliptraResult};
use caliptra_image_types::ImageDigest;
use caliptra_image_types::ImageEccPubKey;
use caliptra_image_types::ImageEccSignature;
use caliptra_image_types::ImageLmsPublicKey;
use caliptra_image_types::ImageLmsSignature;
use caliptra_image_types::ImagePreamble;
use caliptra_image_types::SHA192_DIGEST_WORD_SIZE;
use caliptra_image_types::SHA384_DIGEST_BYTE_SIZE;
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

            let flags: AuthAndStashFlags = cmd.flags.into();
            if !flags.contains(AuthAndStashFlags::SKIP_STASH) {
                // TODO: Stash the image hash
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
