/*++

Licensed under the Apache-2.0 license.

File Name:

    set_auth_manifest.rs

Abstract:

    File contains AuthManifest mailbox command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::verify;
use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_auth_man_types::AuthManifestImageMetadataCollection;
use caliptra_auth_man_types::AuthManifestImageMetadataCollectionHeader;
use caliptra_auth_man_types::AuthManifestPreamble;
use caliptra_auth_man_types::AUTH_MANIFEST_MARKER;
use caliptra_auth_man_types::AUTH_MANIFEST_VENDOR_SIGNATURE_REQURIED_FLAG;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::mailbox_api::SetAuthManifestReq;
use caliptra_common::mailbox_api::{
    MailboxResp, MailboxRespHeader, StashMeasurementReq, StashMeasurementResp,
};
use caliptra_drivers::Array4x12;
use caliptra_drivers::Array4xN;
use caliptra_drivers::AuthManifestImageMetadataArray;
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

pub struct SetAuthManifestCmd;
impl SetAuthManifestCmd {
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

    fn verify_vendor_signed_data(
        auth_manifest_preamble: &AuthManifestPreamble,
        fw_preamble: &ImagePreamble,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        let range = AuthManifestPreamble::vendor_signed_data_range();
        let digest_vendor = Self::sha384_digest(
            sha384,
            auth_manifest_preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        // Verify the vendor ECC signature.
        let vendor_fw_ecc_key = &fw_preamble
            .vendor_pub_keys
            .ecc_pub_keys
            .get(fw_preamble.vendor_ecc_pub_key_idx as usize)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;

        let verify_r = Self::ecc384_verify(
            ecc384,
            &digest_vendor,
            vendor_fw_ecc_key,
            &auth_manifest_preamble.vendor_pub_keys_signatures.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r)
            != caliptra_drivers::Array4xN(
                auth_manifest_preamble.vendor_pub_keys_signatures.ecc_sig.r,
            )
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                &verify_r.0,
                &auth_manifest_preamble.vendor_pub_keys_signatures.ecc_sig.r,
            );
        }

        // Verify vendor LMS signature.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let vendor_fw_lms_key = &fw_preamble
                .vendor_pub_keys
                .lms_pub_keys
                .get(fw_preamble.vendor_lms_pub_key_idx as usize)
                .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;

            let candidate_key = Self::lms_verify(
                sha256,
                &digest_vendor,
                vendor_fw_lms_key,
                &auth_manifest_preamble.vendor_pub_keys_signatures.lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest = HashValue::from(vendor_fw_lms_key.digest);
            if candidate_key != pub_key_digest {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID);
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }

        Ok(())
    }

    fn verify_owner_pub_keys(
        auth_manifest_preamble: &AuthManifestPreamble,
        fw_preamble: &ImagePreamble,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        let range = AuthManifestPreamble::owner_pub_keys_range();
        let digest_owner = Self::sha384_digest(
            sha384,
            auth_manifest_preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        // Verify the owner ECC signature.
        let owner_fw_ecc_key = &fw_preamble.owner_pub_keys.ecc_pub_key;
        let verify_r = Self::ecc384_verify(
            ecc384,
            &digest_owner,
            owner_fw_ecc_key,
            &auth_manifest_preamble.owner_pub_keys_signatures.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r)
            != caliptra_drivers::Array4xN(
                auth_manifest_preamble.owner_pub_keys_signatures.ecc_sig.r,
            )
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                &verify_r.0,
                &auth_manifest_preamble.owner_pub_keys_signatures.ecc_sig.r,
            );
        }

        // Verify owner LMS signature.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let owner_fw_lms_key = &fw_preamble.owner_pub_keys.lms_pub_key;

            let candidate_key = Self::lms_verify(
                sha256,
                &digest_owner,
                owner_fw_lms_key,
                &auth_manifest_preamble.owner_pub_keys_signatures.lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest = HashValue::from(owner_fw_lms_key.digest);
            if candidate_key != pub_key_digest {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID);
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }

        Ok(())
    }

    fn verify_vendor_image_metadata_col(
        auth_manifest_preamble: &AuthManifestPreamble,
        image_metadata_col_digest: &ImageDigest,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        if auth_manifest_preamble.flags & AUTH_MANIFEST_VENDOR_SIGNATURE_REQURIED_FLAG == 0 {
            return Ok(());
        }
        // Verify the vendor ECC signature over the image metadata collection.
        let verify_r = Self::ecc384_verify(
            ecc384,
            image_metadata_col_digest,
            &auth_manifest_preamble.vendor_pub_keys.ecc_pub_key,
            &auth_manifest_preamble
                .vendor_image_metdata_signatures
                .ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r)
            != caliptra_drivers::Array4xN(
                auth_manifest_preamble
                    .vendor_image_metdata_signatures
                    .ecc_sig
                    .r,
            )
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                &verify_r.0,
                &auth_manifest_preamble
                    .vendor_image_metdata_signatures
                    .ecc_sig
                    .r,
            );
        }

        // Verify vendor LMS signature over the image metadata collection.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let candidate_key = Self::lms_verify(
                sha256,
                image_metadata_col_digest,
                &auth_manifest_preamble.vendor_pub_keys.lms_pub_key,
                &auth_manifest_preamble
                    .vendor_image_metdata_signatures
                    .lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest =
                HashValue::from(auth_manifest_preamble.vendor_pub_keys.lms_pub_key.digest);
            if candidate_key != pub_key_digest {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID);
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }
        Ok(())
    }

    fn verify_owner_image_metadata_col(
        auth_manifest_preamble: &AuthManifestPreamble,
        image_metadata_col_digest: &ImageDigest,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        // Verify the owner ECC signature.
        let verify_r = Self::ecc384_verify(
            ecc384,
            image_metadata_col_digest,
            &auth_manifest_preamble.owner_pub_keys.ecc_pub_key,
            &auth_manifest_preamble
                .owner_image_metdata_signatures
                .ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r)
            != caliptra_drivers::Array4xN(
                auth_manifest_preamble
                    .owner_image_metdata_signatures
                    .ecc_sig
                    .r,
            )
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib_git::cfi_assert_eq_12_words(
                &verify_r.0,
                &auth_manifest_preamble
                    .owner_image_metdata_signatures
                    .ecc_sig
                    .r,
            );
        }

        // Verify owner LMS signature.
        if cfi_launder(Self::lms_verify_enabled(soc_ifc)) {
            let candidate_key = Self::lms_verify(
                sha256,
                image_metadata_col_digest,
                &auth_manifest_preamble.owner_pub_keys.lms_pub_key,
                &auth_manifest_preamble
                    .owner_image_metdata_signatures
                    .lms_sig,
            )
            .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest =
                HashValue::from(auth_manifest_preamble.owner_pub_keys.lms_pub_key.digest);
            if candidate_key != pub_key_digest {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID);
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }

        Ok(())
    }

    fn process_image_metadata_col(
        cmd_buf: &[u8],
        auth_manifest_preamble: &AuthManifestPreamble,
        image_metadata_col: &mut AuthManifestImageMetadataCollection,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        if (cmd_buf.len() < size_of::<AuthManifestImageMetadataCollectionHeader>()) {
            return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE);
        }

        let col_size = min(
            cmd_buf.len(),
            size_of::<AuthManifestImageMetadataCollection>(),
        );
        let buf = cmd_buf
            .get(..col_size)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE)?;

        image_metadata_col.as_bytes_mut().copy_from_slice(buf);

        if (image_metadata_col.header.entry_count == 0
            || image_metadata_col.header.entry_count
                > AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT as u32)
        {
            return Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
            );
        }

        let digest_metadata_col = Self::sha384_digest(sha384, buf, 0, col_size as u32)?;

        Self::verify_vendor_image_metadata_col(
            auth_manifest_preamble,
            &digest_metadata_col,
            sha384,
            ecc384,
            sha256,
            soc_ifc,
        )?;

        Self::verify_owner_image_metadata_col(
            auth_manifest_preamble,
            &digest_metadata_col,
            sha384,
            ecc384,
            sha256,
            soc_ifc,
        )?;

        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        let mut cmd = SetAuthManifestReq::default();
        cmd.as_bytes_mut()
            .get_mut(..cmd_args.len())
            .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
            .copy_from_slice(cmd_args);

        // Validate cmd length
        let manifest_size = cmd.manifest_size as usize;
        if manifest_size > cmd.manifest.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        // Validate Manifest length
        let preamble_size = size_of::<AuthManifestPreamble>();
        if (cmd.manifest_size as usize) < preamble_size {
            return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN);
        }

        let auth_manifest_preamble_buf = cmd
            .manifest
            .get(..preamble_size)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN)?;
        let auth_manifest_preamble = AuthManifestPreamble::read_from(auth_manifest_preamble_buf)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN)?;

        // Check if the preamble has the required marker.
        if auth_manifest_preamble.marker != AUTH_MANIFEST_MARKER {
            return Err(CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER);
        }

        // Check if the manifest size is valid.
        if auth_manifest_preamble.size as usize != size_of::<AuthManifestPreamble>() {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH)?;
        }

        let persistent_data = drivers.persistent_data.get_mut();
        // Verify the vendor signed data (vendor public keys + flags).
        Self::verify_vendor_signed_data(
            &auth_manifest_preamble,
            &persistent_data.manifest1.preamble,
            &mut drivers.sha384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &drivers.soc_ifc,
        )?;

        // Verify the owner public keys.
        Self::verify_owner_pub_keys(
            &auth_manifest_preamble,
            &persistent_data.manifest1.preamble,
            &mut drivers.sha384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &drivers.soc_ifc,
        )?;

        Self::process_image_metadata_col(
            &cmd.manifest[preamble_size..],
            &auth_manifest_preamble,
            &mut persistent_data.auth_manifest_image_metadata_col,
            &mut drivers.sha384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &drivers.soc_ifc,
        )?;

        Ok(MailboxResp::default())
    }
}
