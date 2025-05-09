/*++

Licensed under the Apache-2.0 license.

File Name:

    set_auth_manifest.rs

Abstract:

    File contains AuthManifest mailbox command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::Drivers;
use caliptra_auth_man_types::{
    AuthManifestFlags, AuthManifestImageMetadata, AuthManifestImageMetadataCollection,
    AuthManifestPreamble, AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT, AUTH_MANIFEST_MARKER,
};
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_cfi_lib_git::cfi_launder;
use caliptra_common::mailbox_api::SetAuthManifestReq;
use caliptra_drivers::{
    Array4x12, Array4xN, CaliptraError, CaliptraResult, Ecc384, Ecc384PubKey, Ecc384Signature,
    HashValue, Lms, Mldsa87, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature, Sha256, Sha2_512_384,
};
use caliptra_image_types::{
    FwVerificationPqcKeyType, ImageDigest384, ImageDigest512, ImageEccPubKey, ImageEccSignature,
    ImageLmsPublicKey, ImageLmsSignature, ImageMldsaPubKey, ImageMldsaSignature, ImagePreamble,
    MLDSA87_PUB_KEY_BYTE_SIZE, MLDSA87_SIGNATURE_BYTE_SIZE, SHA192_DIGEST_WORD_SIZE,
    SHA384_DIGEST_BYTE_SIZE,
};
use memoffset::offset_of;
use zerocopy::{FromBytes, IntoBytes};
use zeroize::Zeroize;

pub(crate) enum AuthManifestSource<'a> {
    Mailbox,
    Slice(&'a [u8]),
}

pub struct SetAuthManifestCmd;
impl SetAuthManifestCmd {
    fn sha384_digest(
        sha2: &mut Sha2_512_384,
        buf: &[u8],
        offset: u32,
        len: u32,
    ) -> CaliptraResult<ImageDigest384> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = buf
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(sha2.sha384_digest(data)?.0)
    }

    fn sha512_digest(
        sha2: &mut Sha2_512_384,
        buf: &[u8],
        offset: u32,
        len: u32,
    ) -> CaliptraResult<ImageDigest512> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = buf
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(sha2.sha512_digest(data)?.0)
    }

    fn ecc384_verify(
        ecc384: &mut Ecc384,
        digest: &ImageDigest384,
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

    fn lms_verify(
        sha256: &mut Sha256,
        digest: &ImageDigest384,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        for i in 0..digest.len() {
            message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        }
        Lms::default().verify_lms_signature_cfi(sha256, &message, pub_key, sig)
    }

    fn mldsa87_verify(
        mldsa: &mut Mldsa87,
        digest: &ImageDigest512,
        pub_key: &ImageMldsaPubKey,
        sig: &ImageMldsaSignature,
    ) -> CaliptraResult<Mldsa87Result> {
        // Public Key is received in hw format from the image. No conversion needed.
        let pub_key_bytes: [u8; MLDSA87_PUB_KEY_BYTE_SIZE] = pub_key
            .0
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED)?;
        let pub_key = Mldsa87PubKey::read_from_bytes(pub_key_bytes.as_bytes()).or(Err(
            CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED,
        ))?;

        // Signature is received in hw format from the image. No conversion needed.
        let sig_bytes: [u8; MLDSA87_SIGNATURE_BYTE_SIZE] = sig
            .0
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED)?;
        let sig = Mldsa87Signature::read_from_bytes(sig_bytes.as_bytes()).or(Err(
            CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED,
        ))?;

        // digest is received in hw format. No conversion needed.
        let msg = digest.into();

        mldsa.verify(&pub_key, &msg, &sig)
    }

    fn verify_vendor_signed_data(
        auth_manifest_preamble: &AuthManifestPreamble,
        fw_preamble: &ImagePreamble,
        sha2: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87,
        pqc_key_type: FwVerificationPqcKeyType,
    ) -> CaliptraResult<()> {
        let range = AuthManifestPreamble::vendor_signed_data_range();
        let digest_vendor = Self::sha384_digest(
            sha2,
            auth_manifest_preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        // Verify the vendor ECC signature.
        let verify_r = Self::ecc384_verify(
            ecc384,
            &digest_vendor,
            &fw_preamble.vendor_ecc_active_pub_key,
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

        // Verify vendor PQC signature.
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (vendor_fw_lms_key, _) = ImageLmsPublicKey::ref_from_prefix(
                fw_preamble.vendor_pqc_active_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_VENDOR_PUB_KEY_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_pub_keys_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key =
                Self::lms_verify(sha256, &digest_vendor, vendor_fw_lms_key, lms_sig).map_err(
                    |_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
                )?;

            let pub_key_digest = HashValue::from(vendor_fw_lms_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let digest_vendor = Self::sha512_digest(
                sha2,
                auth_manifest_preamble.as_bytes(),
                range.start,
                range.len() as u32,
            )?;

            let (vendor_fw_mldsa_key, _) = ImageMldsaPubKey::ref_from_prefix(
                fw_preamble.vendor_pqc_active_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_PUB_KEY_READ_FAILED,
            ))?;

            let (mldsa_sig, _) = ImageMldsaSignature::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_pub_keys_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_READ_FAILED,
            ))?;

            let result =
                Self::mldsa87_verify(mldsa, &digest_vendor, vendor_fw_mldsa_key, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_INVALID)?;
            }
        }

        Ok(())
    }

    fn verify_owner_pub_keys(
        auth_manifest_preamble: &AuthManifestPreamble,
        fw_preamble: &ImagePreamble,
        sha2: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87,
        pqc_key_type: FwVerificationPqcKeyType,
    ) -> CaliptraResult<()> {
        let range = AuthManifestPreamble::owner_pub_keys_range();
        let digest_owner = Self::sha384_digest(
            sha2,
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
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (owner_fw_lms_key, _) = ImageLmsPublicKey::ref_from_prefix(
                fw_preamble.owner_pub_keys.pqc_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_OWNER_PUB_KEY_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                auth_manifest_preamble
                    .owner_pub_keys_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key = Self::lms_verify(sha256, &digest_owner, owner_fw_lms_key, lms_sig)
                .map_err(|_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            let pub_key_digest = HashValue::from(owner_fw_lms_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let digest_owner = Self::sha512_digest(
                sha2,
                auth_manifest_preamble.as_bytes(),
                range.start,
                range.len() as u32,
            )?;

            let (owner_fw_mldsa_key, _) = ImageMldsaPubKey::ref_from_prefix(
                fw_preamble.owner_pub_keys.pqc_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_PUB_KEY_READ_FAILED,
            ))?;

            let (mldsa_sig, _) = ImageMldsaSignature::ref_from_prefix(
                auth_manifest_preamble
                    .owner_pub_keys_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_READ_FAILED,
            ))?;

            let result = Self::mldsa87_verify(mldsa, &digest_owner, owner_fw_mldsa_key, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_INVALID)?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_vendor_image_metadata_col(
        auth_manifest_preamble: &AuthManifestPreamble,
        image_metadata_col_digest: &ImageDigest384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87,
        sha2: &mut Sha2_512_384,
        pqc_key_type: FwVerificationPqcKeyType,
        metadata_col: &[u8],
    ) -> CaliptraResult<()> {
        let flags = AuthManifestFlags::from(auth_manifest_preamble.flags);
        if !flags.contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED) {
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

        // Verify vendor PQC signature over the image metadata collection.
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (lms_pub_key, _) = ImageLmsPublicKey::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_pub_keys
                    .pqc_pub_key
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_VENDOR_PUB_KEY_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_image_metdata_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key =
                Self::lms_verify(sha256, image_metadata_col_digest, lms_pub_key, lms_sig).map_err(
                    |_| CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
                )?;
            let pub_key_digest = HashValue::from(lms_pub_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let digest_metadata_col =
                Self::sha512_digest(sha2, metadata_col, 0, metadata_col.len() as u32)?;

            let (mldsa_pub_key, _) = ImageMldsaPubKey::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_pub_keys
                    .pqc_pub_key
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_PUB_KEY_READ_FAILED,
            ))?;

            let (mldsa_sig, _) = ImageMldsaSignature::ref_from_prefix(
                auth_manifest_preamble
                    .vendor_image_metdata_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_READ_FAILED,
            ))?;

            let result =
                Self::mldsa87_verify(mldsa, &digest_metadata_col, mldsa_pub_key, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_VENDOR_SIG_INVALID)?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_owner_image_metadata_col(
        auth_manifest_preamble: &AuthManifestPreamble,
        image_metadata_col_digest: &ImageDigest384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87,
        sha2: &mut Sha2_512_384,
        pqc_key_type: FwVerificationPqcKeyType,
        metadata_col: &[u8],
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

        // Verify owner PQC signature.
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (lms_pub_key, _) = ImageLmsPublicKey::ref_from_prefix(
                auth_manifest_preamble
                    .owner_pub_keys
                    .pqc_pub_key
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_OWNER_PUB_KEY_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                auth_manifest_preamble
                    .owner_image_metdata_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key =
                Self::lms_verify(sha256, image_metadata_col_digest, lms_pub_key, lms_sig).map_err(
                    |_| CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
                )?;
            let pub_key_digest = HashValue::from(lms_pub_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib_git::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let digest_metadata_col =
                Self::sha512_digest(sha2, metadata_col, 0, metadata_col.len() as u32)?;

            let (mldsa_pub_key, _) = ImageMldsaPubKey::ref_from_prefix(
                auth_manifest_preamble
                    .owner_pub_keys
                    .pqc_pub_key
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_PUB_KEY_READ_FAILED,
            ))?;

            let (mldsa_sig, _) = ImageMldsaSignature::ref_from_prefix(
                auth_manifest_preamble
                    .owner_image_metdata_signatures
                    .pqc_sig
                    .0
                    .as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_READ_FAILED,
            ))?;

            let result =
                Self::mldsa87_verify(mldsa, &digest_metadata_col, mldsa_pub_key, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_AUTH_MANIFEST_MLDSA_OWNER_SIG_INVALID)?;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_image_metadata_col(
        cmd_buf: &[u8],
        auth_manifest_preamble: &AuthManifestPreamble,
        metadata_persistent: &mut AuthManifestImageMetadataCollection,
        sha2: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87,
        pqc_key_type: FwVerificationPqcKeyType,
    ) -> CaliptraResult<()> {
        if cmd_buf.len() < size_of::<u32>() {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE)?;
        }

        let metadata_size = min(
            cmd_buf.len(),
            size_of::<AuthManifestImageMetadataCollection>(),
        );

        // Resize the buffer to the metadata size.
        let buf = cmd_buf
            .get(..metadata_size)
            .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE)?;

        // Typecast the mailbox buffer to the image metadata collection.
        let metadata_mailbox =
            unsafe { &mut *(buf.as_ptr() as *mut AuthManifestImageMetadataCollection) };

        if metadata_mailbox.entry_count == 0
            || metadata_mailbox.entry_count > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT as u32
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_ENTRY_COUNT)?;
        }

        // Check if the buffer contains the entry count and all the image metadata entries specified by the entry count.
        if buf.len()
            < (size_of::<u32>()
                + metadata_mailbox.entry_count as usize * size_of::<AuthManifestImageMetadata>())
        {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE)?;
        }

        // Calculate the digest of the image metadata collection.
        let digest_metadata_col = Self::sha384_digest(sha2, buf, 0, metadata_size as u32)?;

        Self::verify_vendor_image_metadata_col(
            auth_manifest_preamble,
            &digest_metadata_col,
            ecc384,
            sha256,
            mldsa,
            sha2,
            pqc_key_type,
            buf,
        )?;

        Self::verify_owner_image_metadata_col(
            auth_manifest_preamble,
            &digest_metadata_col,
            ecc384,
            sha256,
            mldsa,
            sha2,
            pqc_key_type,
            buf,
        )?;

        // Sort the image metadata list by firmware ID in place. Also check for duplicate firmware IDs.        let slice =
        let slice =
            &mut metadata_mailbox.image_metadata_list[..metadata_mailbox.entry_count as usize];

        Self::sort_and_check_duplicate_fwid(slice)?;

        // Clear the previous image metadata collection.
        metadata_persistent.zeroize();

        // Copy the image metadata collection to the persistent data.
        metadata_persistent.as_mut_bytes()[..buf.len()].copy_from_slice(buf);

        Ok(())
    }

    fn sort_and_check_duplicate_fwid(
        slice: &mut [AuthManifestImageMetadata],
    ) -> CaliptraResult<()> {
        for i in 1..slice.len() {
            let mut j = i;
            while j > 0 {
                if j >= slice.len() {
                    break;
                }

                match slice[j - 1].fw_id.cmp(&slice[j].fw_id) {
                    core::cmp::Ordering::Greater => {
                        slice.swap(j - 1, j);
                        j -= 1;
                    }
                    core::cmp::Ordering::Equal => {
                        Err(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_DUPLICATE_FIRMWARE_ID)?;
                    }
                    _ => {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        // Validate cmd length
        let manifest_size: usize = {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(SetAuthManifestReq, manifest_size);
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

        if manifest_size > SetAuthManifestReq::MAX_MAN_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let manifest_buf = {
            let offset = offset_of!(SetAuthManifestReq, manifest);
            cmd_args
                .get(offset..offset + manifest_size)
                .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?
        };

        Self::set_auth_manifest(drivers, AuthManifestSource::Slice(manifest_buf))?;
        Ok(0)
    }

    pub(crate) fn set_auth_manifest(
        drivers: &mut Drivers,
        manifest_src: AuthManifestSource,
    ) -> CaliptraResult<()> {
        let manifest_buf = match manifest_src {
            AuthManifestSource::Mailbox => drivers.mbox.raw_mailbox_contents(),
            AuthManifestSource::Slice(buf) => buf,
        };
        let preamble_size = size_of::<AuthManifestPreamble>();
        let auth_manifest_preamble = {
            let err = CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN;
            let bytes = manifest_buf.get(..preamble_size).ok_or(err)?;
            AuthManifestPreamble::ref_from_bytes(bytes).map_err(|_| err)?
        };

        // Check if the preamble has the required marker.
        if auth_manifest_preamble.marker != AUTH_MANIFEST_MARKER {
            Err(CaliptraError::RUNTIME_INVALID_AUTH_MANIFEST_MARKER)?;
        }

        // Check if the manifest size is valid.
        if auth_manifest_preamble.size as usize != size_of::<AuthManifestPreamble>() {
            Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH)?;
        }

        let pqc_key_type =
            FwVerificationPqcKeyType::from_u8(drivers.soc_ifc.fuse_bank().pqc_key_type() as u8)
                .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_INVALID_PQC_KEY_TYPE_IN_FUSE)?;

        let persistent_data = drivers.persistent_data.get_mut();
        // Verify the vendor signed data (vendor public keys + flags).
        Self::verify_vendor_signed_data(
            auth_manifest_preamble,
            &persistent_data.manifest1.preamble,
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &mut drivers.mldsa87,
            pqc_key_type,
        )?;

        // Verify the owner public keys.
        Self::verify_owner_pub_keys(
            auth_manifest_preamble,
            &persistent_data.manifest1.preamble,
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &mut drivers.mldsa87,
            pqc_key_type,
        )?;

        Self::process_image_metadata_col(
            manifest_buf
                .get(preamble_size..)
                .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_INVALID_SIZE)?,
            auth_manifest_preamble,
            &mut persistent_data.auth_manifest_image_metadata_col,
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut drivers.sha256,
            &mut drivers.mldsa87,
            pqc_key_type,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_sorted(slice: &[AuthManifestImageMetadata]) -> bool {
        for i in 0..slice.len() - 1 {
            if slice[i].fw_id > slice[i + 1].fw_id {
                return false;
            }
        }

        true
    }

    #[test]
    fn test_sort_and_duplicate_empty() {
        let resp = SetAuthManifestCmd::sort_and_check_duplicate_fwid(&mut []);
        assert!(resp.is_ok());
    }

    #[test]
    fn test_sort_and_duplicate_sort() {
        let mut list = [
            AuthManifestImageMetadata {
                fw_id: 5,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
            AuthManifestImageMetadata {
                fw_id: 127,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
            AuthManifestImageMetadata {
                fw_id: 48,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
        ];
        let resp = SetAuthManifestCmd::sort_and_check_duplicate_fwid(&mut list);
        assert!(resp.is_ok());
        assert!(is_sorted(&list));
    }

    #[test]
    fn test_sort_and_duplicate_dupe() {
        let mut list = [
            AuthManifestImageMetadata {
                fw_id: 127,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
            AuthManifestImageMetadata {
                fw_id: 5,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
            AuthManifestImageMetadata {
                fw_id: 127,
                flags: 0,
                digest: [0u8; 48],
                ..Default::default()
            },
        ];
        let resp = SetAuthManifestCmd::sort_and_check_duplicate_fwid(&mut list);
        assert_eq!(
            resp.unwrap_err(),
            CaliptraError::RUNTIME_AUTH_MANIFEST_IMAGE_METADATA_LIST_DUPLICATE_FIRMWARE_ID
        );
    }
}
