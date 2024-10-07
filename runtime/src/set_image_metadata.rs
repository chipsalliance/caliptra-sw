/*++

Licensed under the Apache-2.0 license.

File Name:

    set_image_metadata.rs

Abstract:

    File contains AuthManifest mailbox command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::verify;
use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestImageMetadataSet,
    AuthManifestImageMetadataSetHeader, AuthManifestImageMetadataSetWithPublicKeys,
    AuthManifestImageMetadataWithSignatures, AuthManifestPreamble, AuthManifestSignatures,
    AUTH_MANIFEST_MARKER,
};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, SetImageMetadataReq, StashMeasurementReq, StashMeasurementResp,
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

use caliptra_common::cprintln;
use zeroize::Zeroize;

pub struct SetImageMetadataCmd;
impl SetImageMetadataCmd {
    fn sha384_digest(
        sha384: &mut Sha384,
        manifest: &[u8],
        offset: u32,
        len: u32,
    ) -> CaliptraResult<ImageDigest> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = manifest
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(sha384.digest(data)?.0)
    }

    fn ecc384_verify(
        ecc384: &mut Ecc384,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        let pub_key = Ecc384PubKey {
            x: pub_key.x.into(),
            y: pub_key.y.into(),
        };

        let digest: Array4x12 = digest.into();

        let sig = Ecc384Signature {
            r: sig.r.into(),
            s: sig.s.into(),
        };

        ecc384.verify_r(&pub_key, &digest, &sig)
    }

    fn lms_verify_enabled(soc_ifc: &SocIfc) -> bool {
        soc_ifc.fuse_bank().lms_verify() == RomVerifyConfig::EcdsaAndLms
    }

    fn lms_verify(
        sha256: &mut Sha256,
        digest: &ImageDigest,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        for i in 0..digest.len() {
            message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        }
        Lms::default().verify_lms_signature_cfi(sha256, &message, pub_key, sig)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        // Validate cmd length
        let metadata_size: usize = {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(SetImageMetadataReq, metadata_size);
            u32::from_le_bytes(
                cmd_args
                    .get(offset..offset + 4)
                    .ok_or(err)?
                    .try_into()
                    .map_err(|_| err)?,
            )
            .try_into()
            .unwrap()
        };

        if metadata_size > SetImageMetadataReq::MAX_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        // Get a reference to the image metadata.
        let payload = {
            let offset = offset_of!(SetImageMetadataReq, metadata);
            cmd_args
                .get(offset..offset + metadata_size)
                .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?
        };

        // Get the vendor signatures.
        let offset = offset_of!(AuthManifestImageMetadataWithSignatures, vendor_signatures);
        let sig_size = size_of::<AuthManifestSignatures>();
        let vendor_sig = {
            let err = CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_SIGNATURE_SIZE_LT_MIN;
            AuthManifestSignatures::read_from(payload.get(offset..(offset + sig_size)).ok_or(err)?)
                .ok_or(err)?
        };

        // Get the owner signatures.
        let offset = offset_of!(AuthManifestImageMetadataWithSignatures, owner_signatures);
        let owner_sig = {
            let err = CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_SIGNATURE_SIZE_LT_MIN;
            AuthManifestSignatures::read_from(payload.get(offset..(offset + sig_size)).ok_or(err)?)
                .ok_or(err)?
        };

        // Get the image metadata.
        let offset = offset_of!(AuthManifestImageMetadataWithSignatures, image_metadata);
        let image_metadata = payload
            .get(offset..)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_SET_INVALID_SIZE)?;

        // Check if the buffer is at least the size of the header.
        let header_size = size_of::<AuthManifestImageMetadataSetHeader>();
        if image_metadata.len() < header_size {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_SET_INVALID_SIZE)?;
        }

        // Check if the buffer contains all the image hashes.
        let header = {
            let err = CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_SET_INVALID_SIZE;
            AuthManifestImageMetadataSetHeader::read_from(
                image_metadata.get(..header_size).ok_or(err)?,
            )
            .ok_or(err)?
        };

        // Check if the entry count in the header is valid.
        if header.entry_count == 0
            || header.entry_count > AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT as u32
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT)?;
        }

        // Check if the buffer contains all the image hashes specified in the header.
        if image_metadata.len()
            < (header.entry_count as usize * size_of::<AuthManifestImageMetadata>()
                + size_of::<AuthManifestImageMetadataSetHeader>())
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_SET_INVALID_SIZE)?;
        }

        // Take the minimum of the image metadata size and the size of the AuthManifestImageMetadataSet.
        let image_metadata_len = min(
            image_metadata.len(),
            size_of::<AuthManifestImageMetadataSet>(),
        );

        let image_metadata = image_metadata.get(..image_metadata_len).unwrap();

        let persistent_data = drivers.persistent_data.get_mut();

        let image_metadata_set_perst = &mut persistent_data.auth_manifest_image_metadata_set;

        // Hash the image metadata.
        let digest_metadata = Self::sha384_digest(
            &mut drivers.sha384,
            image_metadata,
            0,
            image_metadata_len as u32,
        )?;

        Self::verify_vendor_image_metadata_col(
            image_metadata_set_perst, // For manifest public keys for signature verification.
            &digest_metadata,
            &vendor_sig,
            &mut drivers.sha384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &drivers.soc_ifc,
        )?;

        Self::verify_owner_image_metadata_col(
            image_metadata_set_perst,
            &digest_metadata,
            &owner_sig,
            &mut drivers.sha384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &drivers.soc_ifc,
        )?;

        // Clear the earlier image metadata.
        image_metadata_set_perst.image_metadata.zeroize();

        // Store the image metadata in the persistent data.
        let image_metadata_set_perst = &mut persistent_data
            .auth_manifest_image_metadata_set
            .image_metadata;
        image_metadata_set_perst.as_bytes_mut()[..image_metadata_len]
            .copy_from_slice(image_metadata);

        Ok(MailboxResp::default())
    }

    fn verify_vendor_image_metadata_col(
        image_metadata_set_perst: &AuthManifestImageMetadataSetWithPublicKeys,
        image_metadata_digest: &ImageDigest,
        vendor_sig: &AuthManifestSignatures,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        let flags = AuthManifestFlags::from(image_metadata_set_perst.auth_manifest_flags);
        if !flags.contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED) {
            return Ok(());
        }

        // Verify the vendor ECC signature over the image metadata collection.
        let verify_r = Self::ecc384_verify(
            ecc384,
            image_metadata_digest,
            &image_metadata_set_perst.vendor_man_pub_keys.ecc_pub_key,
            &vendor_sig.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r) != caliptra_drivers::Array4xN(vendor_sig.ecc_sig.r) {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(&verify_r.0, &vendor_sig.ecc_sig.r);
        }

        // Verify vendor LMS signature over the image metadata collection.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let candidate_key = Self::lms_verify(
                sha256,
                image_metadata_digest,
                &image_metadata_set_perst.vendor_man_pub_keys.lms_pub_key,
                &vendor_sig.lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest = HashValue::from(
                image_metadata_set_perst
                    .vendor_man_pub_keys
                    .lms_pub_key
                    .digest,
            );
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }
        Ok(())
    }

    fn verify_owner_image_metadata_col(
        image_metadata_set_perst: &AuthManifestImageMetadataSetWithPublicKeys,
        image_metadata_digest: &ImageDigest,
        owner_sig: &AuthManifestSignatures,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        // Verify the owner ECC signature.
        let verify_r = Self::ecc384_verify(
            ecc384,
            image_metadata_digest,
            &image_metadata_set_perst.owner_man_pub_keys.ecc_pub_key,
            &owner_sig.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r) != caliptra_drivers::Array4xN(owner_sig.ecc_sig.r) {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(&verify_r.0, &owner_sig.ecc_sig.r);
        }

        // Verify owner LMS signature.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let candidate_key = Self::lms_verify(
                sha256,
                image_metadata_digest,
                &image_metadata_set_perst.owner_man_pub_keys.lms_pub_key,
                &owner_sig.lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest = HashValue::from(
                image_metadata_set_perst
                    .owner_man_pub_keys
                    .lms_pub_key
                    .digest,
            );
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }

        Ok(())
    }
}
