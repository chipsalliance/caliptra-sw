/*++

Licensed under the Apache-2.0 license.

File Name:

    set_owner_auth_manifest.rs

Abstract:

    File contains the SET_OWNER_AUTH_MANIFEST mailbox command implementation.
    The Owner Authorization Manifest carries owner-only authorization
    material loaded after `SET_AUTH_MANIFEST`. It is parsed, verified, and
    stored in a dedicated DCCM region; the vendor + owner collection from
    `SET_AUTH_MANIFEST` is never modified by this command.

--*/

use core::cmp::min;
use core::mem::size_of;

use crate::set_auth_manifest::SetAuthManifestCmd;
use crate::Drivers;
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, OwnerAuthManifestFlags, OwnerAuthManifestImageMetadataCollection,
    OwnerAuthManifestPreamble, OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
    OWNER_AUTH_MANIFEST_MARKER,
};
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_cfi_lib::{cfi_assert, cfi_assert_bool, cfi_assert_eq, cfi_launder};
use caliptra_common::mailbox_api::SetOwnerAuthManifestReq;
use caliptra_drivers::{
    Array4xN, CaliptraError, CaliptraResult, Ecc384, HashValue, Lifecycle, Mldsa87, Mldsa87PubKey,
    Mldsa87Result, Mldsa87Signature, Sha256, Sha2_512_384, SocIfc,
};
use caliptra_image_types::{
    FwVerificationPqcKeyType, ImageDigest384, ImageLmsPublicKey, ImageLmsSignature, ImagePreamble,
};
use memoffset::offset_of;
use zerocopy::{FromBytes, IntoBytes};
use zeroize::Zeroize;

pub struct SetOwnerAuthManifestCmd;

impl SetOwnerAuthManifestCmd {
    /// Verify that the manifest's `owner_pub_keys` are signed by the
    /// firmware-image owner key (the trust anchor latched from FMC at
    /// boot via `manifest1.preamble.owner_pub_keys`).
    fn verify_owner_pub_keys_against_fw_owner(
        preamble: &OwnerAuthManifestPreamble,
        fw_preamble: &ImagePreamble,
        sha2: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87<'_>,
        pqc_key_type: FwVerificationPqcKeyType,
    ) -> CaliptraResult<()> {
        // The signed range covers `version..=owner_pub_keys` (the policy
        // fields). Marker and size are validated separately by exact
        // equality against constants.
        let range = OwnerAuthManifestPreamble::owner_signed_data_range();
        let digest = SetAuthManifestCmd::sha384_digest(
            sha2,
            preamble.as_bytes(),
            range.start,
            range.len() as u32,
        )?;

        // Verify the owner ECC signature against the firmware-image
        // owner ECC public key (FMC-bound trust anchor).
        let fw_owner_ecc_key = &fw_preamble.owner_pub_keys.ecc_pub_key;
        let verify_r = SetAuthManifestCmd::ecc384_verify(
            ecc384,
            &digest,
            fw_owner_ecc_key,
            &preamble.owner_pub_keys_signatures.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r) != Array4xN(preamble.owner_pub_keys_signatures.ecc_sig.r) {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib::cfi_assert_eq_12_words(
                &verify_r.0,
                &preamble.owner_pub_keys_signatures.ecc_sig.r,
            );
        }

        // Verify owner PQC signature against the firmware-image owner
        // PQC public key (FMC-bound trust anchor).
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (fw_owner_lms_key, _) = ImageLmsPublicKey::ref_from_prefix(
                fw_preamble.owner_pub_keys.pqc_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                preamble.owner_pub_keys_signatures.pqc_sig.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key =
                SetAuthManifestCmd::lms_verify(sha256, &digest, fw_owner_lms_key, lms_sig)
                    .map_err(|_| {
                        CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID
                    })?;
            let pub_key_digest = HashValue::from(fw_owner_lms_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let owner_data = SetAuthManifestCmd::offset_data(
                preamble.as_bytes(),
                range.start,
                range.len() as u32,
            )?;

            let (fw_owner_mldsa_key, _) =
                Mldsa87PubKey::ref_from_prefix(fw_preamble.owner_pub_keys.pqc_pub_key.0.as_bytes())
                    .or(Err(
                        CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_MLDSA_SIGNATURE_INVALID,
                    ))?;

            let (mldsa_sig, _) = Mldsa87Signature::ref_from_prefix(
                preamble.owner_pub_keys_signatures.pqc_sig.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_MLDSA_SIGNATURE_INVALID,
            ))?;

            let result = mldsa.verify_var(fw_owner_mldsa_key, owner_data, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_OWNER_MLDSA_SIGNATURE_INVALID)?;
            }
        }

        Ok(())
    }

    /// Verify the IMC signatures against the manifest's own
    /// `owner_pub_keys` (which were just verified above to chain to
    /// the firmware-image owner key).
    fn verify_imc_signatures(
        preamble: &OwnerAuthManifestPreamble,
        imc_digest: &ImageDigest384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87<'_>,
        pqc_key_type: FwVerificationPqcKeyType,
        imc_bytes: &[u8],
    ) -> CaliptraResult<()> {
        // Verify the owner ECC signature over the IMC digest.
        let verify_r = SetAuthManifestCmd::ecc384_verify(
            ecc384,
            imc_digest,
            &preamble.owner_pub_keys.ecc_pub_key,
            &preamble.owner_image_metdata_signatures.ecc_sig,
        )
        .map_err(|_| CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_ECC_SIGNATURE_INVALID)?;
        if cfi_launder(verify_r) != Array4xN(preamble.owner_image_metdata_signatures.ecc_sig.r) {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_ECC_SIGNATURE_INVALID)?;
        } else {
            caliptra_cfi_lib::cfi_assert_eq_12_words(
                &verify_r.0,
                &preamble.owner_image_metdata_signatures.ecc_sig.r,
            );
        }

        // Verify owner PQC signature over the IMC.
        if pqc_key_type == FwVerificationPqcKeyType::LMS {
            let (lms_pub_key, _) = ImageLmsPublicKey::ref_from_prefix(
                preamble.owner_pub_keys.pqc_pub_key.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let (lms_sig, _) = ImageLmsSignature::ref_from_prefix(
                preamble.owner_image_metdata_signatures.pqc_sig.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_LMS_SIGNATURE_INVALID,
            ))?;

            let candidate_key =
                SetAuthManifestCmd::lms_verify(sha256, imc_digest, lms_pub_key, lms_sig).map_err(
                    |_| CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_LMS_SIGNATURE_INVALID,
                )?;
            let pub_key_digest = HashValue::from(lms_pub_key.digest);
            if candidate_key != pub_key_digest {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_LMS_SIGNATURE_INVALID)?;
            } else {
                caliptra_cfi_lib::cfi_assert_eq_6_words(&candidate_key.0, &pub_key_digest.0);
            }
        } else {
            let imc_data = SetAuthManifestCmd::offset_data(imc_bytes, 0, imc_bytes.len() as u32)?;

            let (mldsa_pub_key, _) =
                Mldsa87PubKey::ref_from_prefix(preamble.owner_pub_keys.pqc_pub_key.0.as_bytes())
                    .or(Err(
                    CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_MLDSA_SIGNATURE_INVALID,
                ))?;

            let (mldsa_sig, _) = Mldsa87Signature::ref_from_prefix(
                preamble.owner_image_metdata_signatures.pqc_sig.0.as_bytes(),
            )
            .or(Err(
                CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_MLDSA_SIGNATURE_INVALID,
            ))?;

            let result = mldsa.verify_var(mldsa_pub_key, imc_data, mldsa_sig)?;
            if cfi_launder(result) != Mldsa87Result::Success {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_OWNER_MLDSA_SIGNATURE_INVALID)?;
            }
        }

        Ok(())
    }

    /// SVN check against `SS_STRAP_GENERIC[3][7:0]`. The strap is
    /// sampled at reset and locked by `CPTRA_FUSE_WR_DONE`. Skipped
    /// when the lifecycle is `Unprovisioned` or anti-rollback is
    /// disabled, mirroring the policy in
    /// [`SetAuthManifestCmd::verify_svn`].
    pub fn verify_owner_svn(soc_ifc: &SocIfc, svn: u32) -> CaliptraResult<()> {
        let svn_check_required =
            if cfi_launder(soc_ifc.lifecycle() as u32) == Lifecycle::Unprovisioned as u32 {
                cfi_assert_eq(soc_ifc.lifecycle() as u32, Lifecycle::Unprovisioned as u32);
                false
            } else if cfi_launder(soc_ifc.fuse_bank().anti_rollback_disable()) {
                cfi_assert!(soc_ifc.fuse_bank().anti_rollback_disable());
                false
            } else {
                true
            };

        if svn_check_required {
            if cfi_launder(svn) > 255 {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_SVN_GREATER_THAN_MAX)?;
            }
            let min_svn = soc_ifc.ss_owner_manifest_min_svn();
            if cfi_launder(svn) < min_svn {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_SVN_LESS_THAN_MIN)?;
            }
        }

        Ok(())
    }

    /// Parse, verify, and commit the IMC region of the manifest.
    /// On `APPEND_IMAGE_METADATA`, merges the new entries with the
    /// existing collection (rejecting duplicates and exceeding the
    /// max-count cap). Otherwise, replaces the collection wholesale.
    #[allow(clippy::too_many_arguments)]
    fn process_imc(
        cmd_buf: &[u8],
        preamble: &OwnerAuthManifestPreamble,
        persistent: &mut OwnerAuthManifestImageMetadataCollection,
        sha2: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        sha256: &mut Sha256,
        mldsa: &mut Mldsa87<'_>,
        pqc_key_type: FwVerificationPqcKeyType,
    ) -> CaliptraResult<()> {
        if cmd_buf.len() < size_of::<u32>() {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE)?;
        }

        let imc_size = min(
            cmd_buf.len(),
            size_of::<OwnerAuthManifestImageMetadataCollection>(),
        );

        let buf = cmd_buf
            .get(..imc_size)
            .ok_or(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE)?;

        // SAFETY: `OwnerAuthManifestImageMetadataCollection` is
        // `#[repr(C)]` + `FromBytes`, alignment is u32 == 4 which the
        // mailbox buffer satisfies. We only mutate via the sort routine
        // before copying into persistent storage.
        let imc_mailbox =
            unsafe { &mut *(buf.as_ptr() as *mut OwnerAuthManifestImageMetadataCollection) };

        if imc_mailbox.entry_count == 0
            || imc_mailbox.entry_count > OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT as u32
        {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_ENTRY_COUNT)?;
        }

        if buf.len()
            < (size_of::<u32>()
                + imc_mailbox.entry_count as usize * size_of::<AuthManifestImageMetadata>())
        {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE)?;
        }

        let imc_digest = SetAuthManifestCmd::sha384_digest(sha2, buf, 0, imc_size as u32)?;

        Self::verify_imc_signatures(
            preamble,
            &imc_digest,
            ecc384,
            sha256,
            mldsa,
            pqc_key_type,
            buf,
        )?;

        // Sort + duplicate-fwid check on the incoming entries.
        let new_slice = &mut imc_mailbox.image_metadata_list[..imc_mailbox.entry_count as usize];
        SetAuthManifestCmd::sort_and_check_duplicate_fwid(new_slice)?;

        let flags = OwnerAuthManifestFlags::from(preamble.flags);
        if flags.contains(OwnerAuthManifestFlags::APPEND_IMAGE_METADATA) {
            // Append: combined entry_count must fit, no fw_id may
            // collide with an existing entry, and the merged list
            // must remain sorted.
            let existing_count = persistent.entry_count as usize;
            let new_count = imc_mailbox.entry_count as usize;
            let total = existing_count
                .checked_add(new_count)
                .ok_or(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_APPEND_OVERFLOW)?;
            if total > OWNER_AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT {
                Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_APPEND_OVERFLOW)?;
            }

            // Reject duplicate fw_ids across existing+new.
            for new_entry in new_slice.iter() {
                let existing_slice = &persistent.image_metadata_list[..existing_count];
                if existing_slice
                    .binary_search_by(|m| m.fw_id.cmp(&new_entry.fw_id))
                    .is_ok()
                {
                    Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_DUPLICATE_FW_ID)?;
                }
            }

            // Append into the persistent buffer.
            persistent.image_metadata_list[existing_count..total]
                .copy_from_slice(&new_slice[..new_count]);
            persistent.entry_count = total as u32;

            // Re-sort the merged region; the duplicate-check loop above
            // already rejected collisions so this only orders.
            let merged = &mut persistent.image_metadata_list[..total];
            SetAuthManifestCmd::sort_and_check_duplicate_fwid(merged)?;
        } else {
            // Replace: zeroize then copy.
            persistent.zeroize();
            persistent.as_mut_bytes()[..buf.len()].copy_from_slice(buf);
        }

        Ok(())
    }

    #[cfg_attr(feature = "cfi", cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        let manifest_size: usize = {
            let err = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
            let offset = offset_of!(SetOwnerAuthManifestReq, manifest_size);
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

        if manifest_size > SetOwnerAuthManifestReq::MAX_MAN_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let manifest_buf = {
            let offset = offset_of!(SetOwnerAuthManifestReq, manifest);
            cmd_args
                .get(offset..offset + manifest_size)
                .ok_or(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?
        };

        Self::set_owner_auth_manifest(drivers, manifest_buf)?;
        Ok(0)
    }

    pub(crate) fn set_owner_auth_manifest(
        drivers: &mut Drivers,
        manifest_buf: &[u8],
    ) -> CaliptraResult<()> {
        let preamble_size = size_of::<OwnerAuthManifestPreamble>();
        let preamble = {
            let err = CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_PREAMBLE_SIZE_LT_MIN;
            let bytes = manifest_buf.get(..preamble_size).ok_or(err)?;
            OwnerAuthManifestPreamble::ref_from_bytes(bytes).map_err(|_| err)?
        };

        if preamble.marker != OWNER_AUTH_MANIFEST_MARKER {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_INVALID_MARKER)?;
        }

        if preamble.size as usize != preamble_size {
            Err(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_PREAMBLE_SIZE_MISMATCH)?;
        }

        // SVN floor enforced via SS_STRAP_GENERIC[3][7:0].
        Self::verify_owner_svn(&drivers.soc_ifc, preamble.svn)?;

        // Determine PQC key type from the firmware image.
        let persistent_data = drivers.persistent_data.get_mut();
        let manifest_pqc_key_type =
            FwVerificationPqcKeyType::from_u8(persistent_data.rom.manifest1.pqc_key_type)
                .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_INVALID_PQC_KEY_TYPE)?;

        let pqc_key_type = if drivers.soc_ifc.lifecycle() == Lifecycle::Unprovisioned {
            manifest_pqc_key_type
        } else {
            let fuse_pqc_key_type =
                FwVerificationPqcKeyType::from_u8(drivers.soc_ifc.fuse_bank().pqc_key_type() as u8)
                    .ok_or(CaliptraError::RUNTIME_AUTH_MANIFEST_INVALID_PQC_KEY_TYPE_IN_FUSE)?;

            if fuse_pqc_key_type != manifest_pqc_key_type {
                return Err(CaliptraError::RUNTIME_AUTH_MANIFEST_PQC_KEY_TYPE_MISMATCH);
            }

            fuse_pqc_key_type
        };

        let persistent_data = drivers.persistent_data.get_mut();
        drivers.abr.with_mldsa87(|mut mldsa87| {
            // Step 1: verify manifest's owner pub keys against the
            // firmware-image owner trust anchor.
            Self::verify_owner_pub_keys_against_fw_owner(
                preamble,
                &persistent_data.rom.manifest1.preamble,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut mldsa87,
                pqc_key_type,
            )?;

            // Step 2: verify the IMC signatures (made by the manifest's
            // own owner pub keys) and commit per the flags policy.
            Self::process_imc(
                manifest_buf
                    .get(preamble_size..)
                    .ok_or(CaliptraError::RUNTIME_OWNER_AUTH_MANIFEST_IMC_INVALID_SIZE)?,
                preamble,
                &mut persistent_data.fw.owner_auth_manifest_image_metadata_col,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut mldsa87,
                pqc_key_type,
            )
        })?;

        // Record the digest of the full manifest buffer for attestation.
        persistent_data.fw.owner_auth_manifest_digest =
            drivers.sha2_512_384.sha384_digest(manifest_buf)?.0;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use caliptra_auth_man_types::AuthManifestImageMetadata;

    fn entry(fw_id: u32) -> AuthManifestImageMetadata {
        AuthManifestImageMetadata {
            fw_id,
            ..Default::default()
        }
    }

    #[test]
    fn test_owner_imc_sort_and_dedup_uses_shared_helper() {
        let mut entries = [entry(7), entry(2), entry(5), entry(2)];
        // Duplicate fw_id (2) must be detected.
        let res = SetAuthManifestCmd::sort_and_check_duplicate_fwid(&mut entries);
        assert!(res.is_err());

        let mut entries = [entry(7), entry(2), entry(5)];
        let res = SetAuthManifestCmd::sort_and_check_duplicate_fwid(&mut entries);
        assert!(res.is_ok());
        assert_eq!(entries[0].fw_id, 2);
        assert_eq!(entries[1].fw_id, 5);
        assert_eq!(entries[2].fw_id, 7);
    }
}
