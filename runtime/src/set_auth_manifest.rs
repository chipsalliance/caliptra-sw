/*++

Licensed under the Apache-2.0 license.

File Name:

    set_auth_manifest.rs

Abstract:

    File contains AuthManifest mailbox command.

--*/

use core::mem::size_of;

use crate::{dpe_crypto::DpeCrypto, CptraDpeTypes, DpePlatform, Drivers};
use caliptra_auth_man_types::AuthManifestImageMetadataCollection;
use caliptra_auth_man_types::AuthManifestImageMetadataCollectionHeader;
use caliptra_auth_man_types::AuthManifestPreamble;
use caliptra_auth_man_types::AUTH_MANIFEST_MARKER;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::cprintln;
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

    fn verify_vendor_pub_keys(
        persistent_data: &mut PersistentData,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        let auth_manifest_preamble = &mut persistent_data.auth_manifest_preamble;

        let range = AuthManifestPreamble::vendor_pub_keys_range();
        let digest_vendor = Self::sha384_digest(
            sha384,
            auth_manifest_preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        let fw_preamble = &persistent_data.manifest1.preamble;

        // Verify the vendor ECC signature.
        let vendor_fw_ecc_key =
            &fw_preamble.vendor_pub_keys.ecc_pub_keys[fw_preamble.vendor_ecc_pub_key_idx as usize];

        let verify_r = Self::ecc384_verify(
            ecc384,
            &digest_vendor,
            &vendor_fw_ecc_key,
            &auth_manifest_preamble.vendor_pub_keys_signatures.ecc_sig,
        )?;
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
            let vendor_fw_lms_key = &fw_preamble.vendor_pub_keys.lms_pub_keys
                [fw_preamble.vendor_lms_pub_key_idx as usize];

            let candidate_key = Self::lms_verify(
                sha256,
                &digest_vendor,
                vendor_fw_lms_key,
                &auth_manifest_preamble.vendor_pub_keys_signatures.lms_sig,
            )?;
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
        persistent_data: &mut PersistentData,
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        soc_ifc: &SocIfc,
    ) -> CaliptraResult<()> {
        let auth_manifest_preamble = &mut persistent_data.auth_manifest_preamble;

        let range = AuthManifestPreamble::owner_pub_keys_range();
        let digest_owner = Self::sha384_digest(
            sha384,
            auth_manifest_preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        let fw_preamble = &persistent_data.manifest1.preamble;

        // Verify the owner ECC signature.
        let owner_fw_ecc_key = &fw_preamble.owner_pub_keys.ecc_pub_key;
        let verify_r = Self::ecc384_verify(
            ecc384,
            &digest_owner,
            &owner_fw_ecc_key,
            &auth_manifest_preamble.owner_pub_keys_signatures.ecc_sig,
        )?;
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
            )?;
            let pub_key_digest = HashValue::from(owner_fw_lms_key.digest);
            if candidate_key != pub_key_digest {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID);
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        }

        Ok(())
    }

    fn process_image_metadata_list(
        cmd_buf: &[u8],
        persistent_data: &mut PersistentData,
    ) -> CaliptraResult<()> {
        if ((cmd_buf.len() < size_of::<AuthManifestImageMetadataCollectionHeader>())
            || (cmd_buf.len() > size_of::<AuthManifestImageMetadataCollection>()))
        {
            return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE);
        }

        let image_metadata_list = &mut persistent_data.auth_manifest_image_metadata_col;
        image_metadata_list.as_bytes_mut()[..].copy_from_slice(cmd_buf);

        if (image_metadata_list.header.entry_count == 0
            || image_metadata_list.header.entry_count
                > AUTH_MANIFEST_IMAGE_METADATA_LIST_MAX_COUNT as u32)
        {
            return Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT,
            );
        }

        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<MailboxResp> {
        cprintln!("[auth_man] In execute");

        if cmd_args.len() > size_of::<AuthManifestPreamble>() {
            cprintln!("[auth_man] AuthManifestPreamble size is valid");
            let persistent_data = drivers.persistent_data.get_mut();
            cprintln!("[auth_man] Got persistent_data");
            let auth_manifest_preamble = &mut persistent_data.auth_manifest_preamble;
            cprintln!("[auth_man] Got auth_manifest_preamble");
            auth_manifest_preamble.as_bytes_mut()[..size_of::<AuthManifestPreamble>()]
                .copy_from_slice(cmd_args);
            cprintln!("[auth_man] Copied auth_manifest_preamble");

            // Check if the preamble has the required marker.
            if auth_manifest_preamble.marker != AUTH_MANIFEST_MARKER {
                return Err(CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER);
            }
            cprintln!("[auth_man] AuthManifestPreamble marker is valid");

            // Check if the manifest size is valid.
            if auth_manifest_preamble.size as usize != size_of::<AuthManifestPreamble>() {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH)?;
            }

            // Verify the vendor public keys.
            Self::verify_vendor_pub_keys(
                persistent_data,
                &mut drivers.sha384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &drivers.soc_ifc,
            )?;

            // Verify the owner public keys.
            Self::verify_owner_pub_keys(
                persistent_data,
                &mut drivers.sha384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &drivers.soc_ifc,
            )?;
        } else {
            return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN);
        }

        let persistent_data = drivers.persistent_data.get_mut();
        Self::process_image_metadata_list(
            &cmd_args[size_of::<AuthManifestPreamble>()..],
            persistent_data,
        )?;

        Ok(MailboxResp::default())
    }
}
