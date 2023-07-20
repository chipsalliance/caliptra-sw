/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier.rs

Abstract:

    This file is the main implementaiton of Caliptra Image Verifier.

--*/

use core::num::NonZeroU32;

use crate::*;
use caliptra_drivers::*;
use caliptra_image_types::*;
use memoffset::offset_of;

const ZERO_DIGEST: ImageDigest = [0u32; SHA384_DIGEST_WORD_SIZE];

/// Header Info
struct HeaderInfo<'a> {
    vendor_ecc_pub_key_idx: u32,
    vendor_lms_pub_key_idx: u32,
    owner_lms_pub_key_idx: u32,
    vendor_pub_key_revocation: VendorPubKeyRevocation,
    vendor_info: (&'a ImageEccPubKey, &'a ImageEccSignature),
    vendor_lms_info: (&'a ImageLmsPublicKey, &'a ImageLmsSignature),
    owner_info: Option<(&'a ImageEccPubKey, &'a ImageEccSignature)>,
    owner_lms_info: Option<(&'a ImageLmsPublicKey, &'a ImageLmsSignature)>,
    owner_pub_keys_digest: ImageDigest,
}

/// TOC Info
struct TocInfo<'a> {
    len: u32,
    digest: &'a ImageDigest,
}

/// Image Info
struct ImageInfo<'a> {
    fmc: &'a ImageTocEntry,
    runtime: &'a ImageTocEntry,
}

/// Image Verifier
pub struct ImageVerifier<Env: ImageVerificationEnv> {
    /// Verifiaction Environment
    env: Env,
}

impl<Env: ImageVerificationEnv> ImageVerifier<Env> {
    /// Create a new instance `ImageVerifier`
    ///
    /// # Arguments
    ///
    /// * `env` - Environment
    pub fn new(env: Env) -> Self {
        Self { env }
    }

    /// Verify Caliptra image
    ///
    /// # Arguments
    ///
    /// * `manifest` - Image Manifest
    /// * `image`    - Image to verify
    /// * `reason`   - Reset Reason
    ///
    /// # Returns
    ///
    /// * `ImageVerificationInfo` - Image verifiaction information success
    pub fn verify(
        &mut self,
        manifest: &ImageManifest,
        img_bundle_sz: u32,
        reason: ResetReason,
    ) -> CaliptraResult<ImageVerificationInfo> {
        // Check if manifest has required marker
        if manifest.marker != MANIFEST_MARKER {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH)?;
        }

        // Check if manifest size is valid
        if manifest.size as usize != core::mem::size_of::<ImageManifest>() {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH)?;
        }

        // Verify the preamble
        let preamble = &manifest.preamble;
        let header_info = self.verify_preamble(preamble, reason);
        let header_info = okref(&header_info)?;

        // Verify Header
        let header = &manifest.header;
        let toc_info = self.verify_header(header, header_info);
        let toc_info = okref(&toc_info)?;

        // Verify TOC
        let image_info = self.verify_toc(manifest, toc_info, img_bundle_sz);
        let image_info = okref(&image_info)?;

        // Verify FMC
        let (fmc_info, fmc_log_info) = self.verify_fmc(image_info.fmc, reason)?;

        // Verify Runtime
        let (runtime_info, rt_log_info) = self.verify_runtime(image_info.runtime)?;

        let info = ImageVerificationInfo {
            vendor_ecc_pub_key_idx: header_info.vendor_ecc_pub_key_idx,
            vendor_pub_keys_digest: self.make_vendor_key_digest(header_info)?,
            owner_pub_keys_digest: header_info.owner_pub_keys_digest,
            fmc: fmc_info,
            runtime: runtime_info,
            log_info: ImageVerificationLogInfo {
                vendor_ecc_pub_key_idx: header_info.vendor_ecc_pub_key_idx,
                fuse_vendor_pub_key_revocation: header_info.vendor_pub_key_revocation,
                fmc_log_info,
                rt_log_info,
            },
        };

        Ok(info)
    }

    /// Verify Preamble
    fn verify_preamble<'a>(
        &mut self,
        preamble: &'a ImagePreamble,
        reason: ResetReason,
    ) -> CaliptraResult<HeaderInfo<'a>> {
        // Verify Vendor Public Key Digest
        self.verify_vendor_pk_digest()?;

        // Verify Owner Public Key Digest
        let owner_pk_digest = self.verify_owner_pk_digest(reason)?;

        // Verify Vendor Key Index
        let (vendor_ecc_pub_key_idx, vendor_pub_key_revocation) =
            self.verify_vendor_ecc_pk_idx(preamble, reason)?;

        if vendor_ecc_pub_key_idx >= VENDOR_ECC_KEY_COUNT {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VEN_PUB_KEY_IDX_OUT_OF_BOUNDS)?;
        }

        // Vendor Information
        let vendor_info = (
            &preamble.vendor_pub_keys.ecc_pub_keys[vendor_ecc_pub_key_idx as usize],
            &preamble.vendor_sigs.ecc_sig,
        );

        let vendor_lms_pub_key_idx = preamble.vendor_lms_pub_key_idx;
        if vendor_lms_pub_key_idx >= VENDOR_LMS_KEY_COUNT {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUBKEY_INDEX_OUT_OF_BOUNDS);
        }

        let vendor_lms_info = (
            &preamble.vendor_pub_keys.lms_pub_keys[vendor_lms_pub_key_idx as usize],
            &preamble.vendor_sigs.lms_sig,
        );

        // Owner Information
        let (owner_lms_pub_key_idx, owner_pub_keys_digest, owner_info, owner_lms_info) =
            if let Some(digest) = owner_pk_digest {
                if preamble.owner_lms_pub_key_idx >= OWNER_LMS_KEY_COUNT {
                    return Err(
                        CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_PUBKEY_INDEX_OUT_OF_BOUNDS,
                    );
                }

                (
                    preamble.owner_lms_pub_key_idx,
                    digest,
                    Some((
                        &preamble.owner_pub_keys.ecc_pub_key,
                        &preamble.owner_sigs.ecc_sig,
                    )),
                    Some((
                        &preamble.owner_pub_keys.lms_pub_keys
                            [preamble.owner_lms_pub_key_idx as usize],
                        &preamble.owner_sigs.lms_sig,
                    )),
                )
            } else {
                (OWNER_LMS_KEY_COUNT, ZERO_DIGEST, None, None)
            };

        let info = HeaderInfo {
            vendor_ecc_pub_key_idx,
            vendor_lms_pub_key_idx,
            vendor_info,
            vendor_lms_info,
            owner_lms_pub_key_idx,
            owner_lms_info,
            owner_pub_keys_digest,
            owner_info,
            vendor_pub_key_revocation,
        };

        Ok(info)
    }

    /// Verify Vendor ECC Public Key Index
    fn verify_vendor_ecc_pk_idx(
        &mut self,
        preamble: &ImagePreamble,
        reason: ResetReason,
    ) -> CaliptraResult<(u32, VendorPubKeyRevocation)> {
        const SECOND_LAST_KEY_IDX: u32 = VENDOR_ECC_KEY_COUNT - 2;
        const LAST_KEY_IDX: u32 = VENDOR_ECC_KEY_COUNT - 1;

        let key_idx = preamble.vendor_ecc_pub_key_idx;
        let revocation = self.env.vendor_pub_key_revocation();

        match key_idx {
            0..=SECOND_LAST_KEY_IDX => {
                let key = VendorPubKeyRevocation::from_bits_truncate(0x01u32 << key_idx);
                if revocation.contains(key) {
                    Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_REVOKED)?;
                }
            }
            LAST_KEY_IDX => {
                // The last key is never revoked
            }
            _ => Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS)?,
        }

        if reason == ResetReason::UpdateReset {
            let expected = self.env.vendor_pub_key_idx_dv();
            if expected != key_idx {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PUB_KEY_IDX_MISMATCH)?;
            }
        }

        Ok((key_idx, revocation))
    }

    /// Verify vendor public key digest
    fn verify_vendor_pk_digest(&mut self) -> Result<(), NonZeroU32> {
        // We skip vendor public key check in unprovisioned state
        if self.env.dev_lifecycle() == Lifecycle::Unprovisioned {
            return Ok(());
        }

        // Read expected value from environment
        let expected = self.env.vendor_pub_key_digest();

        // Vendor public key digest must never be zero
        if expected == ZERO_DIGEST {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID)?;
        }

        let range = ImageManifest::vendor_pub_keys_range();

        let actual = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE)?;

        if expected != actual {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH)?;
        }

        Ok(())
    }

    /// Verify owner public key digest
    fn verify_owner_pk_digest(
        &mut self,
        reason: ResetReason,
    ) -> CaliptraResult<Option<ImageDigest>> {
        let range = ImageManifest::owner_pub_key_range();

        let actual = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_FAILURE)?;

        let fuses_digest = self.env.owner_pub_key_digest_fuses();

        if fuses_digest != ZERO_DIGEST && fuses_digest != actual {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_MISMATCH)?;
        }

        if reason == ResetReason::UpdateReset {
            let cold_boot_digest = self.env.owner_pub_key_digest_dv();
            if cold_boot_digest != actual {
                return Err(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_OWNER_DIGEST_FAILURE);
            }
        }

        Ok(Some(actual))
    }

    /// Verify Header
    fn verify_header<'a>(
        &mut self,
        header: &'a ImageHeader,
        info: &HeaderInfo,
    ) -> CaliptraResult<TocInfo<'a>> {
        // Calculate the digest for the header
        let range = ImageManifest::header_range();
        let vendor_header_len = offset_of!(ImageHeader, owner_data);

        // Vendor header digest is calculated up to the owner_data field.
        let digest_vendor = self
            .env
            .sha384_digest(range.start, vendor_header_len as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE)?;

        let digest_owner = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_HEADER_DIGEST_FAILURE)?;

        // Verify vendor signature
        let (pub_key, sig) = info.vendor_info;
        let (lms_pub_key, lms_sig) = info.vendor_lms_info;
        self.verify_vendor_sig(&digest_vendor, pub_key, lms_pub_key, sig, lms_sig)?;

        // Verify the ECC public key index used verify header signature is encoded
        // in the header
        if header.vendor_ecc_pub_key_idx != info.vendor_ecc_pub_key_idx {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH)?;
        }

        if header.vendor_lms_pub_key_idx != info.vendor_lms_pub_key_idx {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH);
        }

        if let Some((owner_lms_pub_key, owner_lms_sig)) = info.owner_lms_info {
            if header.owner_lms_pub_key_idx != info.owner_lms_pub_key_idx {
                return Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_PUB_KEY_INDEX_MISMATCH);
            }

            self.verify_owner_lms_sig(&digest_owner, owner_lms_pub_key, owner_lms_sig)?;
        }

        // Verify owner signature
        if let Some((pub_key, sig)) = info.owner_info {
            self.verify_owner_sig(&digest_owner, pub_key, sig)?;
        }

        let verif_info = TocInfo {
            len: header.toc_len,
            digest: &header.toc_digest,
        };

        Ok(verif_info)
    }

    /// Verify Owner Signature
    fn verify_owner_sig(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<()> {
        if pub_key.x == ZERO_DIGEST || pub_key.y == ZERO_DIGEST {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG)?;
        }
        if sig.r == ZERO_DIGEST || sig.s == ZERO_DIGEST {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG)?;
        }

        let result = self
            .env
            .ecc384_verify(digest, pub_key, sig)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE)?;

        if !result {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID)?;
        }

        Ok(())
    }

    /// Verify Vendor Signature
    fn verify_vendor_sig(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        lms_pub_key: &ImageLmsPublicKey,
        sig: &ImageEccSignature,
        lms_sig: &ImageLmsSignature,
    ) -> CaliptraResult<()> {
        if pub_key.x == ZERO_DIGEST || pub_key.y == ZERO_DIGEST {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG)?;
        }
        if sig.r == ZERO_DIGEST || sig.s == ZERO_DIGEST {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG)?;
        }

        let mut result = self
            .env
            .ecc384_verify(digest, pub_key, sig)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE)?;

        if !result {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID)?;
        }

        result = self
            .env
            .lms_verify(digest, lms_pub_key, lms_sig)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE)?;
        if !result {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID);
        }

        Ok(())
    }

    /// Verify owner LMS Signature
    fn verify_owner_lms_sig(
        &mut self,
        digest: &ImageDigest,
        lms_pub_key: &ImageLmsPublicKey,
        lms_sig: &ImageLmsSignature,
    ) -> CaliptraResult<()> {
        let result = self
            .env
            .lms_verify(digest, lms_pub_key, lms_sig)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_VERIFY_FAILURE)?;
        if !result {
            return Err(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_SIGNATURE_INVALID);
        }

        Ok(())
    }

    /// Verify Table of Contents
    fn verify_toc<'a>(
        &mut self,
        manifest: &'a ImageManifest,
        verify_info: &TocInfo,
        img_bundle_sz: u32,
    ) -> CaliptraResult<ImageInfo<'a>> {
        if verify_info.len != MAX_TOC_ENTRY_COUNT {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID)?;
        }

        let range = ImageManifest::toc_range();

        let actual = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_FAILURES)?;

        if *verify_info.digest != actual {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH)?;
        }

        // Image length donot exceeed the Image Bundle size
        let img_len: u64 = manifest.size as u64
            + manifest.fmc.image_size() as u64
            + manifest.runtime.image_size() as u64;

        if img_len > img_bundle_sz.into() {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE)?;
        }

        // Check if fmc and runtime section overlap.
        let fmc_range = manifest.fmc.image_range();
        let runtime_range = manifest.runtime.image_range();
        if fmc_range.contains(&runtime_range.start)
            || fmc_range.contains(&(runtime_range.end - 1))
            || runtime_range.contains(&fmc_range.start)
            || runtime_range.contains(&(fmc_range.end - 1))
        {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)?;
        }

        // Ensure the fmc section is before the runtime section in the manifest.
        if fmc_range.end > runtime_range.start {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER)?;
        }

        // Check if fmc and runtime images don't overlap on loading in ICCM.
        let fmc_load_addr_start = manifest.fmc.load_addr;
        let fmc_load_addr_end = fmc_load_addr_start + manifest.fmc.image_size() - 1;
        let runtime_load_addr_start = manifest.runtime.load_addr;
        let runtime_load_addr_end = runtime_load_addr_start + manifest.runtime.image_size() - 1;

        if fmc_load_addr_start <= runtime_load_addr_end
            && fmc_load_addr_end >= runtime_load_addr_start
        {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP)?;
        }

        let info = ImageInfo {
            fmc: &manifest.fmc,
            runtime: &manifest.runtime,
        };

        Ok(info)
    }

    // Check if SVN check is required
    fn svn_check_required(&mut self) -> bool {
        // If device is unprovisioned or if anti-rollback is disabled, don't check the SVN.
        !(self.env.dev_lifecycle() == Lifecycle::Unprovisioned || self.env.anti_rollback_disable())
    }

    /// Verify FMC
    fn verify_fmc(
        &mut self,
        verify_info: &ImageTocEntry,
        reason: ResetReason,
    ) -> CaliptraResult<(ImageVerificationExeInfo, ImageSvnLogInfo)> {
        let range = verify_info.image_range();

        let actual = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE)?;

        if verify_info.digest != actual {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH)?;
        }

        // TODO: Perform following Address check
        // Entry Point is within the image
        if !self.env.iccm_range().contains(&verify_info.load_addr) {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_INVALID)?;
        }
        if verify_info.load_addr % 4 != 0 {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_LOAD_ADDR_UNALIGNED)?;
        }

        if !self.env.iccm_range().contains(&verify_info.entry_point) {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID)?;
        }
        if verify_info.entry_point % 4 != 0 {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_UNALIGNED)?;
        }

        if self.svn_check_required() {
            if verify_info.svn > 32 {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_GREATER_THAN_MAX_SUPPORTED)?;
            }

            if verify_info.svn < verify_info.min_svn {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_MIN_SUPPORTED)?;
            }

            if verify_info.svn < self.env.fmc_svn() {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_FMC_SVN_LESS_THAN_FUSE)?;
            }
        }

        let effective_fuse_svn =
            Self::effective_fuse_svn(self.env.fmc_svn(), self.env.anti_rollback_disable());

        if reason == ResetReason::UpdateReset && actual != self.env.get_fmc_digest_dv() {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH)?;
        }

        let info = ImageVerificationExeInfo {
            load_addr: verify_info.load_addr,
            entry_point: verify_info.entry_point,
            svn: verify_info.svn,
            effective_fuse_svn,
            digest: verify_info.digest,
            size: verify_info.size,
        };

        let log_info: ImageSvnLogInfo = ImageSvnLogInfo {
            manifest_svn: verify_info.svn,
            manifest_min_svn: verify_info.min_svn,
            fuse_svn: self.env.fmc_svn(),
        };

        Ok((info, log_info))
    }

    /// Verify Runtime
    fn verify_runtime(
        &mut self,
        verify_info: &ImageTocEntry,
    ) -> CaliptraResult<(ImageVerificationExeInfo, ImageSvnLogInfo)> {
        let range = verify_info.image_range();

        let actual = self
            .env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE)?;

        if verify_info.digest != actual {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH)?;
        }

        // TODO: Perform following Address checks
        // 3. Entry Point is within the image

        if !self.env.iccm_range().contains(&verify_info.load_addr) {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_INVALID)?;
        }
        if verify_info.load_addr % 4 != 0 {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_LOAD_ADDR_UNALIGNED)?;
        }
        if !self.env.iccm_range().contains(&verify_info.entry_point) {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID)?;
        }
        if verify_info.entry_point % 4 != 0 {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_UNALIGNED)?;
        }

        if self.svn_check_required() {
            if verify_info.svn > 64 {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_GREATER_THAN_MAX_SUPPORTED)?;
            }

            if verify_info.svn < verify_info.min_svn {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_MIN_SUPPORTED)?;
            }

            if verify_info.svn < self.env.runtime_svn() {
                Err(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_SVN_LESS_THAN_FUSE)?;
            }
        }

        let effective_fuse_svn =
            Self::effective_fuse_svn(self.env.runtime_svn(), self.env.anti_rollback_disable());

        let info = ImageVerificationExeInfo {
            load_addr: verify_info.load_addr,
            entry_point: verify_info.entry_point,
            svn: verify_info.svn,
            effective_fuse_svn,
            digest: verify_info.digest,
            size: verify_info.size,
        };

        let log_info: ImageSvnLogInfo = ImageSvnLogInfo {
            manifest_svn: verify_info.svn,
            manifest_min_svn: verify_info.min_svn,
            fuse_svn: self.env.runtime_svn(),
        };

        Ok((info, log_info))
    }

    /// Calculates a digest of the vendor key that signed the image.
    ///
    /// TODO: include the LMS key in the digest.
    fn make_vendor_key_digest(&mut self, info: &HeaderInfo) -> CaliptraResult<ImageDigest> {
        let range = ImageManifest::vendor_ecc_pub_key_range(info.vendor_ecc_pub_key_idx);

        if range.is_empty() {
            Err(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_OUT_OF_BOUNDS)?;
        }

        self.env
            .sha384_digest(range.start, range.len() as u32)
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_FAILURE)
    }

    /// Calculates the effective fuse SVN.
    ///
    /// If anti-rollback is disabled, the effective fuse-SVN is zero.
    /// Otherwise, it is SVN-fuses.
    fn effective_fuse_svn(fuse_svn: u32, anti_rollback_disable: bool) -> u32 {
        if anti_rollback_disable {
            0_u32
        } else {
            fuse_svn
        }
    }
}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use super::*;

    const DUMMY_DATA: [u32; 12] = [
        0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef,
        0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef,
    ];
    const VENDOR_ECC_PUBKEY: ImageEccPubKey = ImageEccPubKey {
        x: DUMMY_DATA,
        y: DUMMY_DATA,
    };
    const VENDOR_ECC_SIG: ImageEccSignature = ImageEccSignature {
        r: DUMMY_DATA,
        s: DUMMY_DATA,
    };
    fn vendor_lms_pubkey() -> ImageLmsPublicKey {
        ImageLmsPublicKey::default()
    }
    fn vendor_lms_sig() -> ImageLmsSignature {
        ImageLmsSignature::default()
    }
    const OWNER_ECC_PUBKEY: ImageEccPubKey = ImageEccPubKey {
        x: DUMMY_DATA,
        y: DUMMY_DATA,
    };
    const OWNER_ECC_SIG: ImageEccSignature = ImageEccSignature {
        r: DUMMY_DATA,
        s: DUMMY_DATA,
    };

    #[test]
    fn test_vendor_ecc_pk_idx_update_rst() {
        let test_env = TestEnv {
            verify_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let preamble = ImagePreamble::default();

        let result = verifier.verify_vendor_ecc_pk_idx(&preamble, ResetReason::UpdateReset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_vendor_ecc_pk_idx_mismatch_update_rst() {
        let test_env = TestEnv {
            verify_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);

        let preamble = ImagePreamble {
            vendor_ecc_pub_key_idx: 2,
            ..Default::default()
        };

        let result = verifier.verify_vendor_ecc_pk_idx(&preamble, ResetReason::UpdateReset);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_VENDOR_PUB_KEY_IDX_MISMATCH)
        );
    }

    #[test]
    fn test_owner_pk_digest_update_rst() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            digest: DUMMY_DATA,
            ..Default::default()
        };

        let mut verifier = ImageVerifier::new(test_env);
        let preamble = ImagePreamble::default();

        let result = verifier.verify_preamble(&preamble, ResetReason::UpdateReset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fmc_update_rst() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            digest: DUMMY_DATA,
            fmc_digest: DUMMY_DATA,
            ..Default::default()
        };

        let mut verifier = ImageVerifier::new(test_env);

        let verify_info = ImageTocEntry {
            digest: DUMMY_DATA,
            load_addr: 0x40000000,
            entry_point: 0x40000000,
            ..Default::default()
        };

        let result = verifier.verify_fmc(&verify_info, ResetReason::UpdateReset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fmc_mismatch_update_rst() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            digest: DUMMY_DATA,
            ..Default::default()
        };

        let mut verifier = ImageVerifier::new(test_env);
        let verify_info = ImageTocEntry {
            digest: DUMMY_DATA,
            load_addr: 0x40000000,
            entry_point: 0x40000000,
            ..Default::default()
        };

        let result = verifier.verify_fmc(&verify_info, ResetReason::UpdateReset);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_UPDATE_RESET_FMC_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn test_owner_verify_preamble_update_rst() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            digest: DUMMY_DATA,
            fmc_digest: DUMMY_DATA,
            ..Default::default()
        };

        let mut verifier = ImageVerifier::new(test_env);
        let preamble = ImagePreamble::default();

        let result = verifier.verify_preamble(&preamble, ResetReason::UpdateReset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_manifest_marker() {
        let manifest = ImageManifest::default();
        let mut verifier = ImageVerifier::new(TestEnv::default());
        let result = verifier.verify(&manifest, manifest.size, ResetReason::ColdReset);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_MARKER_MISMATCH)
        );
    }

    #[test]
    fn test_manifest_size() {
        let manifest = ImageManifest {
            marker: MANIFEST_MARKER,
            size: 100,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(TestEnv::default());
        let result = verifier.verify(&manifest, manifest.size, ResetReason::ColdReset);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_MANIFEST_SIZE_MISMATCH)
        );
    }

    #[test]
    fn test_preamble_vendor_pubkey_digest() {
        let preamble = ImagePreamble::default();
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let result = verifier.verify_preamble(&preamble, ResetReason::ColdReset);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID)
        );
    }

    #[test]
    fn test_preamble_owner_pubkey_digest() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            digest: DUMMY_DATA,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let preamble = ImagePreamble::default();

        let result = verifier.verify_preamble(&preamble, ResetReason::ColdReset);
        assert!(result.is_ok());
    }

    #[test]
    fn test_preamble_vendor_pubkey() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let preamble = ImagePreamble::default();
        let result = verifier.verify_preamble(&preamble, ResetReason::ColdReset);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn test_header_vendor_pubkey_invalid_arg() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let ecc_pubkey = ImageEccPubKey::default();
        let ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&ImageEccPubKey::default(), &ImageEccSignature::default()),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&ecc_pubkey, &ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_PUB_KEY_DIGEST_INVALID_ARG)
        );
    }

    #[test]
    fn test_header_vendor_signature_invalid_arg() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &ImageEccSignature::default()),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            // verified error
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG)
        );
    }

    #[test]
    fn test_header_vendor_signature_invalid() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID)
        );
    }

    #[test]
    fn test_header_vendor_lms_signature_invalid() {
        let test_env = TestEnv {
            lifecycle: Lifecycle::Production,
            vendor_pub_key_digest: DUMMY_DATA,
            owner_pub_key_digest: DUMMY_DATA,
            verify_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            vendor_pub_key_revocation: Default::default(),
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID)
        );
    }

    #[test]
    fn test_header_incorrect_pubkey_index() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 1,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INDEX_MISMATCH)
        );
    }

    #[test]
    fn test_header_incorrect_lms_pubkey_index() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 1,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_PUB_KEY_INDEX_MISMATCH)
        );
    }

    #[test]
    fn test_header_incorrect_owner_lms_pubkey_index() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 1,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_LMS_PUB_KEY_INDEX_MISMATCH)
        );
    }

    #[test]
    fn test_header_owner_pubkey_invalid_arg() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_pubkey = ImageEccPubKey::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&owner_ecc_pubkey, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_PUB_KEY_DIGEST_INVALID_ARG)
        );
    }

    #[test]
    fn test_header_owner_signature_invalid_arg() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader::default();
        let owner_ecc_sig = ImageEccSignature::default();
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&OWNER_ECC_PUBKEY, &owner_ecc_sig)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let result = verifier.verify_header(&header, &header_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG)
        );
    }

    #[test]
    fn test_header_success() {
        let test_env = TestEnv {
            verify_result: true,
            verify_lms_result: true,
            ..Default::default()
        };
        let mut verifier = ImageVerifier::new(test_env);
        let header = ImageHeader {
            toc_len: 100,
            toc_digest: DUMMY_DATA,
            ..Default::default()
        };
        let owner_lms_pubkey = ImageLmsPublicKey::default();
        let owner_lms_sig = ImageLmsSignature::default();
        let header_info: HeaderInfo = HeaderInfo {
            vendor_ecc_pub_key_idx: 0,
            vendor_lms_pub_key_idx: 0,
            owner_lms_pub_key_idx: 0,
            vendor_info: (&VENDOR_ECC_PUBKEY, &VENDOR_ECC_SIG),
            vendor_lms_info: (&vendor_lms_pubkey(), &vendor_lms_sig()),
            owner_info: Some((&OWNER_ECC_PUBKEY, &OWNER_ECC_SIG)),
            owner_lms_info: Some((&owner_lms_pubkey, &owner_lms_sig)),
            owner_pub_keys_digest: ImageDigest::default(),
            vendor_pub_key_revocation: Default::default(),
        };
        let toc_info = verifier.verify_header(&header, &header_info).unwrap();
        assert_eq!(toc_info.len, 100);
        assert_eq!(toc_info.digest, &DUMMY_DATA);
    }

    #[test]
    fn test_toc_incorrect_length() {
        let manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT / 2,
            digest: &ImageDigest::default(),
        };
        let result = verifier.verify_toc(&manifest, &toc_info, manifest.size);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_TOC_ENTRY_COUNT_INVALID)
        );
    }

    #[test]
    fn test_toc_digest_mismatch() {
        let manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &DUMMY_DATA,
        };
        let result = verifier.verify_toc(&manifest, &toc_info, manifest.size);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_TOC_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn test_toc_fmc_rt_overlap() {
        let mut manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &ImageDigest::default(),
        };

        // Case 0:
        // [-FMC--]
        // [--RT--]
        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 0;
        manifest.runtime.size = 100;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 1:
        // [-FMC--]
        //        [--RT--]
        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 99;
        manifest.runtime.size = 200;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 2:
        // [-FMC--]
        //   [-RT-]
        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 5;
        manifest.runtime.size = 100;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 3:
        //   [-FMC-]
        // [---RT--]
        manifest.fmc.offset = 5;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 0;
        manifest.runtime.size = 100;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 4:
        //        [-FMC--]
        // [--RT--]
        manifest.runtime.offset = 0;
        manifest.runtime.size = 100;
        manifest.fmc.offset = 99;
        manifest.fmc.size = 200;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 5:
        //  [---FMC---]
        //    [-RT-]
        manifest.fmc.offset = 100;
        manifest.fmc.size = 500;
        manifest.runtime.offset = 150;
        manifest.runtime.size = 200;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );

        // Case 6:
        //  [----RT----]
        //    [-FMC-]
        manifest.runtime.offset = 0;
        manifest.runtime.size = 200;
        manifest.fmc.offset = 20;
        manifest.fmc.size = 30;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_OVERLAP)
        );
    }

    #[test]
    fn test_size_failure() {
        let mut manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &ImageDigest::default(),
        };

        // [-FMC--]
        // [--RT--]
        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 100;
        manifest.runtime.size = 200;
        let result = verifier.verify_toc(&manifest, &toc_info, 100);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_IMAGE_LEN_MORE_THAN_BUNDLE_SIZE)
        );
    }

    #[test]
    fn test_size_success() {
        let mut manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &ImageDigest::default(),
        };

        // [-FMC--]
        // [--RT--]
        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 100;
        manifest.runtime.size = 200;
        manifest.fmc.load_addr = 0x1000;
        manifest.runtime.load_addr = 0x2000;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_toc_fmc_rt_order() {
        let mut manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &ImageDigest::default(),
        };

        // [-FMC--]
        // [--RT--]
        manifest.runtime.offset = 0;
        manifest.runtime.size = 100;
        manifest.fmc.offset = 100;
        manifest.fmc.size = 200;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_INCORRECT_ORDER)
        );
    }

    #[test]
    fn test_fmc_rt_load_address_range_overlap() {
        let mut manifest = ImageManifest::default();
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let toc_info = TocInfo {
            len: MAX_TOC_ENTRY_COUNT,
            digest: &ImageDigest::default(),
        };

        manifest.fmc.offset = 0;
        manifest.fmc.size = 100;
        manifest.runtime.offset = 100;
        manifest.runtime.size = 200;

        // Case 1:
        // [-FMC--]
        //      [--RT--]
        manifest.fmc.load_addr = 0;
        manifest.fmc.size = 100;
        manifest.runtime.load_addr = 50;
        manifest.runtime.size = 100;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP)
        );

        // Case 2:
        //      [-FMC--]
        //  [--RT--]
        manifest.fmc.load_addr = 50;
        manifest.fmc.size = 100;
        manifest.runtime.load_addr = 0;
        manifest.runtime.size = 100;
        let result = verifier.verify_toc(
            &manifest,
            &toc_info,
            manifest.size + manifest.fmc.image_size() + manifest.runtime.image_size(),
        );

        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_RUNTIME_LOAD_ADDR_OVERLAP)
        );
    }

    #[test]
    fn test_fmc_digest_mismatch() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let verify_info = ImageTocEntry {
            digest: DUMMY_DATA,
            ..Default::default()
        };
        let result = verifier.verify_fmc(&verify_info, ResetReason::ColdReset);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn test_fmc_success() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let verify_info = ImageTocEntry {
            load_addr: 0x40000000,
            entry_point: 0x40000000,
            svn: 1,
            size: 100,
            ..Default::default()
        };

        let result = verifier.verify_fmc(&verify_info, ResetReason::ColdReset);
        assert!(result.is_ok());
        let (info, _log_info) = result.unwrap();
        assert_eq!(info.load_addr, 0x40000000);
        assert_eq!(info.entry_point, 0x40000000);
        assert_eq!(info.svn, 1);
        assert_eq!(info.size, 100);
    }

    #[test]
    fn test_rt_digest_mismatch() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let verify_info = ImageTocEntry {
            digest: DUMMY_DATA,
            ..Default::default()
        };
        let result = verifier.verify_runtime(&verify_info);
        assert_eq!(
            result.err(),
            Some(CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH)
        );
    }

    #[test]
    fn test_rt_success() {
        let test_env = TestEnv::default();
        let mut verifier = ImageVerifier::new(test_env);
        let verify_info = ImageTocEntry {
            load_addr: 0x40000000,
            entry_point: 0x40000000,
            svn: 1,
            size: 100,
            ..Default::default()
        };
        let result = verifier.verify_runtime(&verify_info);
        assert!(result.is_ok());
        let (info, _log_info) = result.unwrap();
        assert_eq!(info.load_addr, 0x40000000);
        assert_eq!(info.entry_point, 0x40000000);
        assert_eq!(info.svn, 1);
        assert_eq!(info.size, 100);
    }

    struct TestEnv {
        digest: ImageDigest,
        fmc_digest: ImageDigest,
        verify_result: bool,
        verify_lms_result: bool,
        vendor_pub_key_digest: ImageDigest,
        vendor_pub_key_revocation: VendorPubKeyRevocation,
        owner_pub_key_digest: ImageDigest,
        lifecycle: Lifecycle,
    }

    impl Default for TestEnv {
        fn default() -> Self {
            TestEnv {
                digest: ImageDigest::default(),
                fmc_digest: ImageDigest::default(),
                verify_result: false,
                verify_lms_result: false,
                vendor_pub_key_digest: ImageDigest::default(),
                vendor_pub_key_revocation: VendorPubKeyRevocation::default(),
                owner_pub_key_digest: ImageDigest::default(),
                lifecycle: Lifecycle::Unprovisioned,
            }
        }
    }

    impl ImageVerificationEnv for TestEnv {
        fn sha384_digest(&mut self, _offset: u32, _len: u32) -> CaliptraResult<ImageDigest> {
            Ok(self.digest)
        }

        fn ecc384_verify(
            &mut self,
            _digest: &ImageDigest,
            _pub_key: &ImageEccPubKey,
            _sig: &ImageEccSignature,
        ) -> CaliptraResult<bool> {
            Ok(self.verify_result)
        }

        fn lms_verify(
            &mut self,
            _digest: &ImageDigest,
            _pub_key: &ImageLmsPublicKey,
            _sig: &ImageLmsSignature,
        ) -> CaliptraResult<bool> {
            Ok(self.verify_lms_result)
        }

        fn vendor_pub_key_digest(&self) -> ImageDigest {
            self.vendor_pub_key_digest
        }

        fn vendor_pub_key_revocation(&self) -> VendorPubKeyRevocation {
            self.vendor_pub_key_revocation
        }

        fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
            self.owner_pub_key_digest
        }

        fn anti_rollback_disable(&self) -> bool {
            false
        }

        fn dev_lifecycle(&self) -> Lifecycle {
            self.lifecycle
        }

        fn vendor_pub_key_idx_dv(&self) -> u32 {
            0
        }

        fn owner_pub_key_digest_dv(&self) -> ImageDigest {
            self.owner_pub_key_digest
        }

        fn get_fmc_digest_dv(&self) -> ImageDigest {
            self.fmc_digest
        }

        fn fmc_svn(&self) -> u32 {
            0
        }

        fn runtime_svn(&self) -> u32 {
            0
        }

        fn iccm_range(&self) -> Range<u32> {
            Range {
                start: 0x40000000,
                end: 0x40000000 + (128 * 1024),
            }
        }
    }
}
