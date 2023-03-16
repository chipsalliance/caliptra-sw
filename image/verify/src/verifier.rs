/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier.rs

Abstract:

    This file is the main implementaiton of Caliptra Image Verifier.

--*/

use crate::*;
use caliptra_image_types::*;
use caliptra_lib::*;

const ZERO_DIGEST: ImageDigest = [0u32; SHA384_DIGEST_WORD_SIZE];

caliptra_err_def! {
    ImageVerifier,
    ImageVerifierErr {
        ManifestMarkerMismatch = 1,
        ManifestSizeMismatch = 2,
        VendorPubKeyDigestInvalid = 3,
        VendorPubKeyDigestFailure = 4,
        VendorPubKeyDigestMismatch = 5,
        OwnerPubKeyDigestFailure = 6,
        OwnerPubKeyDigestMismatch = 7,
        VendorEccPubKeyIndexOutOfBounds = 8,
        VendorEccPubKeyRevoked = 9,
        HeaderDigestFailure = 10,
        VendorEccVerifyFailure = 11,
        VendorEccSignatureInvalid = 12,
        VendorEccPubKeyIndexMismatch = 13,
        OwnerEccVerifyFailure = 14,
        OwnerEccSignatureInvalid = 15,
        TocEntryCountInvalid = 16,
        TocDigestFailures = 17,
        TocDigestMismatch = 18,
        FmcDigestFailure = 19,
        FmcDigestMismatch = 20,
        RuntimeDigestFailure = 21,
        RuntimeDigestMismatch = 22,
    }
}

/// Header Info
struct HeaderInfo<'a> {
    vendor_ecc_pub_key_idx: u32,
    vendor_info: (&'a ImageEccPubKey, &'a ImageEccSignature),
    owner_info: Option<(&'a ImageEccPubKey, &'a ImageEccSignature)>,
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
        &self,
        manifest: &ImageManifest,
        image: Env::Image,
        _reason: ResetReason,
    ) -> CaliptraResult<ImageVerificationInfo> {
        // Check if manifest has required marker
        if manifest.marker() != MANIFEST_MARKER {
            raise_err!(ManifestMarkerMismatch)
        }

        // Check if manifest size is valid
        if manifest.size() as usize != core::mem::size_of::<ImageManifest>() {
            raise_err!(ManifestSizeMismatch)
        }

        // Verify the preamble
        let preamble = manifest.preamble();
        let header_info = self.verify_preamble(image, preamble)?;

        // Verify Header
        let header = manifest.header();
        let toc_info = self.verify_header(image, header, &header_info)?;

        // Verify TOC
        let image_info = self.verify_toc(image, manifest, &toc_info)?;

        // Verify FMC
        let fmc_info = self.verify_fmc(image, image_info.fmc)?;

        // Verify Runtime
        let runtime_info = self.verify_runtime(image, image_info.runtime)?;

        let mut info = ImageVerificationInfo::default();
        info.set_vendor_ecc_pub_key_idx(header_info.vendor_ecc_pub_key_idx)
            .set_owner_pub_keys_digest(header_info.owner_pub_keys_digest)
            .set_fmc(fmc_info)
            .set_runtime(runtime_info);

        Ok(info)
    }

    /// Verify Preamble
    fn verify_preamble<'a>(
        &self,
        image: Env::Image,
        preamble: &'a ImagePreamble,
    ) -> CaliptraResult<HeaderInfo<'a>> {
        // Verify Vendor Public Key Digest
        self.verify_vendor_pk_digest(image)?;

        // Verify Owner Public Key Digest
        let owner_pk_digest = self.verify_owner_pk_digest(image)?;

        // Verify Vendor Key Index
        let vendor_ecc_pub_key_idx = self.verify_vendor_ecc_pk_idx(preamble, image)?;

        // Vendor Information
        let vendor_info = (
            &preamble.vendor_pub_keys().ecc_pub_keys()[vendor_ecc_pub_key_idx as usize],
            preamble.vendor_sigs().ecc_sig(),
        );

        // Owner Information
        let (owner_pub_keys_digest, owner_info) = if let Some(digest) = owner_pk_digest {
            (
                digest,
                Some((
                    preamble.owner_pub_keys().ecc_pub_key(),
                    preamble.owner_sigs().ecc_sig(),
                )),
            )
        } else {
            (ZERO_DIGEST, None)
        };

        let info = HeaderInfo {
            vendor_ecc_pub_key_idx,
            vendor_info,
            owner_pub_keys_digest,
            owner_info,
        };

        Ok(info)
    }

    /// Verify Vendor ECC Public Key Index
    fn verify_vendor_ecc_pk_idx(
        &self,
        preamble: &ImagePreamble,
        image: Env::Image,
    ) -> CaliptraResult<u32> {
        const SECOND_LAST_KEY_IDX: u32 = VENDOR_ECC_KEY_COUNT - 2;
        const LAST_KEY_IDX: u32 = VENDOR_ECC_KEY_COUNT - 1;

        let key_idx = preamble.vendor_ecc_pub_key_idx();
        let revocation = self.env.vendor_pub_key_revocation(image);

        match key_idx {
            0..=SECOND_LAST_KEY_IDX => {
                let key = VendorPubKeyRevocation::from_bits_truncate(0x01u32 << key_idx);
                if revocation.contains(key) {
                    raise_err!(VendorEccPubKeyRevoked)
                }
            }
            LAST_KEY_IDX => {
                // The last key is never revoked
            }
            _ => raise_err!(VendorEccPubKeyIndexOutOfBounds),
        }

        Ok(key_idx)
    }

    /// Verify vendor public key digest
    fn verify_vendor_pk_digest(
        &self,
        image: <Env as ImageVerificationEnv>::Image,
    ) -> Result<(), u32> {
        // We skip vendor public key check in unprovisioned state
        if self.env.dev_lifecycle(image) == Lifecycle::Unprovisioned {
            return Ok(());
        }

        // Read expected value from environment
        let expected = self.env.vendor_pub_key_digest(image);

        // Vendor public key digest must never be zero
        if expected == ZERO_DIGEST {
            raise_err!(VendorPubKeyDigestInvalid)
        }

        let range = ImageManifest::vendor_pub_key_range();

        let actual = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(VendorPubKeyDigestFailure))?;

        if expected != actual {
            raise_err!(VendorPubKeyDigestMismatch)
        }

        Ok(())
    }

    /// Verify owner public key digest
    fn verify_owner_pk_digest(&self, image: Env::Image) -> CaliptraResult<Option<ImageDigest>> {
        let expected = self.env.owner_pub_key_digest(image);

        // Skip Verification if owner public key digest is zero
        if expected == ZERO_DIGEST {
            return Ok(None);
        }

        let range = ImageManifest::owner_pub_key_range();

        let actual = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(OwnerPubKeyDigestFailure))?;

        if expected != actual {
            raise_err!(OwnerPubKeyDigestMismatch)
        }

        Ok(Some(expected))
    }

    /// Verify Header
    fn verify_header<'a>(
        &self,
        image: Env::Image,
        header: &'a ImageHeader,
        info: &HeaderInfo,
    ) -> CaliptraResult<TocInfo<'a>> {
        // Calculate the digest for the header
        let range = ImageManifest::header_range();
        let digest = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(HeaderDigestFailure))?;

        // Verify vendor signature
        let (pub_key, sig) = info.vendor_info;
        self.verify_vendor_sig(image, &digest, pub_key, sig)?;

        // Verify the ECC public key index used verify header signature is encoded
        // in the header
        if header.vendor_ecc_pub_key_idx() != info.vendor_ecc_pub_key_idx {
            raise_err!(VendorEccPubKeyIndexMismatch)
        }

        // Verify owner signature
        if let Some((pub_key, sig)) = info.owner_info {
            self.verify_owner_sig(image, &digest, pub_key, sig)?;
        }

        let verif_info = TocInfo {
            len: header.toc_len(),
            digest: header.toc_digest(),
        };

        Ok(verif_info)
    }

    /// Verify Owner Signature
    fn verify_owner_sig(
        &self,
        image: Env::Image,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<()> {
        //
        // TODO: Check signature and public key are not all zeros
        //

        let result = self
            .env
            .ecc384_verify(image, digest, pub_key, sig)
            .map_err(|_| err_u32!(OwnerEccVerifyFailure))?;

        if !result {
            raise_err!(OwnerEccSignatureInvalid)
        }

        Ok(())
    }

    /// Verify Vendor Signature
    fn verify_vendor_sig(
        &self,
        image: Env::Image,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<()> {
        //
        // TODO: Check signature and public key are not all zeros
        //

        let result = self
            .env
            .ecc384_verify(image, digest, pub_key, sig)
            .map_err(|_| err_u32!(VendorEccVerifyFailure))?;

        if !result {
            raise_err!(VendorEccSignatureInvalid)
        }

        Ok(())
    }

    /// Verify Table of Contents
    fn verify_toc<'a>(
        &self,
        image: Env::Image,
        manifest: &'a ImageManifest,
        verify_info: &TocInfo,
    ) -> CaliptraResult<ImageInfo<'a>> {
        if verify_info.len != MAX_TOC_ENTRY_COUNT {
            raise_err!(TocEntryCountInvalid)
        }

        let range = ImageManifest::toc_range();

        let actual = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(TocDigestFailures))?;

        if *verify_info.digest != actual {
            raise_err!(TocDigestMismatch)
        }

        // TODO: Perform Following offset length length checks
        // 1. Image length donot exceeed the Image Bundle size
        // 2. FMC and runtime offset and length donot overlap
        // 3. FMC is before the runtime in image

        let info = ImageInfo {
            fmc: manifest.fmc(),
            runtime: manifest.runtime(),
        };

        Ok(info)
    }

    /// Verify FMC
    fn verify_fmc(
        &self,
        image: Env::Image,
        verify_info: &ImageTocEntry,
    ) -> CaliptraResult<ImageVerificationExeInfo> {
        let range = verify_info.image_range();

        let actual = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(FmcDigestFailure))?;

        if *verify_info.digest() != actual {
            raise_err!(FmcDigestMismatch)
        }

        // TODO: Perform following Address checks
        // 1. Load address is a valid ICCM Address
        // 2. Entry Point is a valid ICCM Address
        // 3. Entry Point is within the image

        let mut info = ImageVerificationExeInfo::default();
        info.set_load_addr(verify_info.load_addr())
            .set_entry_point(verify_info.entry_point())
            .set_svn(verify_info.svn())
            .set_digest(*verify_info.digest())
            .set_size(verify_info.size());

        // TODO: SVN Check
        // 0. Skip SVN check in unprovisioned mode or when antirollback is disabled
        // 1. SVN is not more than 32
        // 2. SVN is valid against min_svn and fuse_svn

        Ok(info)
    }

    /// Verify Runtime
    fn verify_runtime(
        &self,
        image: Env::Image,
        verify_info: &ImageTocEntry,
    ) -> CaliptraResult<ImageVerificationExeInfo> {
        let range = verify_info.image_range();

        let actual = self
            .env
            .sha384_digest(image, range.start, range.len() as u32)
            .map_err(|_| err_u32!(RuntimeDigestFailure))?;

        if *verify_info.digest() != actual {
            raise_err!(RuntimeDigestMismatch)
        }

        // TODO: Perform following Address checks
        // 1. Load address is a valid ICCM Address
        // 2. Entry Point is a valid ICCM Address
        // 3. Entry Point is within the image

        let mut info = ImageVerificationExeInfo::default();
        info.set_load_addr(verify_info.load_addr())
            .set_entry_point(verify_info.entry_point())
            .set_svn(verify_info.svn())
            .set_digest(*verify_info.digest())
            .set_size(verify_info.size());

        // TODO: SVN Check
        // 0. Skip SVN check in unprovisioned mode or when antirollback is disabled
        // 1. SVN is not more than 64
        // 2. SVN is valid against min_svn and fuse_svn

        Ok(info)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_marker() {
        let manifest = ImageManifest::default();
        let verifier = ImageVerifier::new(TestEnv::default());
        let result = verifier.verify(&manifest, (), ResetReason::ColdReset);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(err_u32!(ManifestMarkerMismatch)));
    }

    #[test]
    fn test_manifest_size() {
        let mut manifest = ImageManifest::default();
        manifest.set_marker(MANIFEST_MARKER);
        let verifier = ImageVerifier::new(TestEnv::default());
        let result = verifier.verify(&manifest, (), ResetReason::ColdReset);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(err_u32!(ManifestSizeMismatch)));
    }

    #[derive(Default)]
    struct TestEnv {
        digest: ImageDigest,
        verify_result: bool,
        vendor_pub_key_digest: ImageDigest,
        vendor_pub_key_revocation: VendorPubKeyRevocation,
        owner_pub_key_digest: ImageDigest,
    }

    impl ImageVerificationEnv for TestEnv {
        type Image = ();

        fn sha384_digest(
            &self,
            _image: Self::Image,
            _offset: u32,
            _len: u32,
        ) -> CaliptraResult<ImageDigest> {
            Ok(self.digest)
        }

        fn ecc384_verify(
            &self,
            _image: Self::Image,
            _digest: &ImageDigest,
            _pub_key: &ImageEccPubKey,
            _sig: &ImageEccSignature,
        ) -> CaliptraResult<bool> {
            Ok(self.verify_result)
        }

        fn vendor_pub_key_digest(&self, _image: Self::Image) -> ImageDigest {
            self.vendor_pub_key_digest
        }

        fn vendor_pub_key_revocation(&self, _image: Self::Image) -> VendorPubKeyRevocation {
            self.vendor_pub_key_revocation
        }

        fn owner_pub_key_digest(&self, _image: Self::Image) -> ImageDigest {
            self.owner_pub_key_digest
        }

        fn anti_rollback_disable(&self, _image: Self::Image) -> bool {
            false
        }

        fn dev_lifecycle(&self, _image: Self::Image) -> Lifecycle {
            Lifecycle::Unprovisioned
        }
    }
}
