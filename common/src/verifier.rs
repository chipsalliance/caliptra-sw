/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier.rs

Abstract:

    Image Verification support routines.

--*/

use caliptra_drivers::*;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use core::ops::Range;
use zerocopy::{AsBytes, FromBytes};

use caliptra_drivers::memory_layout::ICCM_RANGE;

/// ROM Verification Environemnt
pub struct FirmwareImageVerificationEnv<'a, 'b> {
    pub sha256: &'a mut Sha256,
    pub sha2_512_384: &'a mut Sha2_512_384,
    pub soc_ifc: &'a mut SocIfc,
    pub ecc384: &'a mut Ecc384,
    pub mldsa87: &'a mut Mldsa87,
    pub data_vault: &'a mut DataVault,
    pub pcr_bank: &'a mut PcrBank,
    pub image: &'b [u8],
}

impl<'a, 'b> ImageVerificationEnv for &mut FirmwareImageVerificationEnv<'a, 'b> {
    /// Calculate 384 digest using SHA2 Engine
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest384> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha384_digest(data)?.0)
    }

    /// Calculate 512 digest using SHA2 Engine
    fn sha512_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest512> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        let data = self
            .image
            .get(offset as usize..)
            .ok_or(err)?
            .get(..len as usize)
            .ok_or(err)?;
        Ok(self.sha2_512_384.sha512_digest(data)?.0)
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
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

        self.ecc384.verify_r(&pub_key, &digest, &sig)
    }

    fn lms_verify(
        &mut self,
        digest: &ImageDigest384,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        for i in 0..digest.len() {
            message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        }
        Lms::default().verify_lms_signature_cfi(self.sha256, &message, pub_key, sig)
    }

    fn mldsa87_verify(
        &mut self,
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
        let pub_key = Mldsa87PubKey::read_from(pub_key_bytes.as_bytes())
            .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED)?;

        // Signature is received in hw format from the image. No conversion needed.
        let sig_bytes: [u8; MLDSA87_SIGNATURE_BYTE_SIZE] = sig
            .0
            .as_bytes()
            .try_into()
            .map_err(|_| CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED)?;
        let sig = Mldsa87Signature::read_from(sig_bytes.as_bytes())
            .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_MLDSA_TYPE_CONVERSION_FAILED)?;

        // digest is received in hw format. No conversion needed.
        let msg = digest.into();

        self.mldsa87.verify(&pub_key, &msg, &sig)
    }

    /// Retrieve Vendor Public Key Info Digest
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().vendor_pub_key_info_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor ECC key index saved in data vault on cold boot
    fn vendor_ecc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.ecc_vendor_pk_index()
    }

    /// Get the vendor LMS key index saved in data vault on cold boot
    fn vendor_pqc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.pqc_vendor_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.fmc_tci().into()
    }

    // Get Runtime fuse SVN
    fn runtime_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().runtime_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        ICCM_RANGE
    }

    fn set_fw_extended_error(&mut self, err: u32) {
        self.soc_ifc.set_fw_extended_error(err);
    }
}
