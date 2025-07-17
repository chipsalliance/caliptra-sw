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
use zerocopy::{FromBytes, IntoBytes};

use caliptra_drivers::memory_layout::ICCM_RANGE;

/// ROM Verification Environemnt
pub struct FirmwareImageVerificationEnv<'a, 'b> {
    pub sha256: &'a mut Sha256,
    pub sha2_512_384: &'a mut Sha2_512_384,
    pub sha2_512_384_acc: &'a mut Sha2_512_384Acc,
    pub soc_ifc: &'a mut SocIfc,
    pub ecc384: &'a mut Ecc384,
    pub mldsa87: &'a mut Mldsa87,
    pub data_vault: &'a DataVault,
    pub pcr_bank: &'a mut PcrBank,
    pub image: &'b [u8],
    pub dma: &'a Dma,
    pub persistent_data: &'a PersistentData,
}

impl FirmwareImageVerificationEnv<'_, '_> {
    fn image_in_mcu(&self) -> bool {
        self.soc_ifc.has_ss_staging_area()
    }

    fn create_dma_recovery<'a>(soc_ifc: &'a SocIfc, dma: &'a Dma) -> DmaRecovery<'a> {
        DmaRecovery::new(
            soc_ifc.recovery_interface_base_addr().into(),
            soc_ifc.caliptra_base_axi_addr().into(),
            soc_ifc.mci_base_addr().into(),
            dma,
        )
    }
}

impl ImageVerificationEnv for &mut FirmwareImageVerificationEnv<'_, '_> {
    /// Calculate 384 digest using SHA2 Engine
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest384> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        if self.image_in_mcu() {
            let dma = FirmwareImageVerificationEnv::create_dma_recovery(self.soc_ifc, self.dma);
            let result = dma.sha384_mcu_sram(self.sha2_512_384_acc, offset, len)?;
            Ok(result.into())
        } else {
            let data = self
                .image
                .get(offset as usize..)
                .ok_or(err)?
                .get(..len as usize)
                .ok_or(err)?;
            let result = self.sha2_512_384.sha384_digest(data)?.0;
            Ok(result)
        }
    }

    /// Calculate 512 digest using SHA2 Engine
    fn sha512_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest512> {
        let err = CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS;
        if self.image_in_mcu() {
            let dma = FirmwareImageVerificationEnv::create_dma_recovery(self.soc_ifc, self.dma);
            let result = dma.sha512_mcu_sram(self.sha2_512_384_acc, offset, len)?;
            Ok(result.into())
        } else {
            let data = self
                .image
                .get(offset as usize..)
                .ok_or(err)?
                .get(..len as usize)
                .ok_or(err)?;
            Ok(self.sha2_512_384.sha512_digest(data)?.0)
        }
    }

    fn sha384_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest384> {
        if self.image_in_mcu() {
            // For MCU case, use the existing sha384_digest function
            self.sha384_digest(offset, len).map_err(|_| digest_failure)
        } else {
            let mut digest = Array4x12::default();

            if let Some(mut sha_acc_op) = self
                .sha2_512_384_acc
                .try_start_operation(ShaAccLockState::NotAcquired)?
            {
                sha_acc_op
                    .digest_384(len, offset, false, &mut digest)
                    .map_err(|_| digest_failure)?;
            } else {
                Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
            };
            Ok(digest.0)
        }
    }

    fn sha512_acc_digest(
        &mut self,
        offset: u32,
        len: u32,
        digest_failure: CaliptraError,
    ) -> CaliptraResult<ImageDigest512> {
        if self.image_in_mcu() {
            // For MCU case, use the existing sha512_digest function
            self.sha512_digest(offset, len).map_err(|_| digest_failure)
        } else {
            let mut digest = Array4x16::default();

            if let Some(mut sha_acc_op) = self
                .sha2_512_384_acc
                .try_start_operation(ShaAccLockState::NotAcquired)?
            {
                sha_acc_op
                    .digest_512(len, offset, false, &mut digest)
                    .map_err(|_| digest_failure)?;
            } else {
                Err(CaliptraError::KAT_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
            };

            Ok(digest.0)
        }
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
        msg: &[u8],
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

        self.mldsa87.verify_var(&pub_key, msg, &sig)
    }

    /// Retrieve Vendor Public Key Info Digest
    fn vendor_pub_key_info_digest_fuses(&self) -> ImageDigest384 {
        self.soc_ifc.fuse_bank().vendor_pub_key_info_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorEccPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Vendor MLDSA Public Key Revocation Bitmask
    fn vendor_mldsa_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_mldsa_pub_key_revocation()
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
        self.data_vault.vendor_ecc_pk_index()
    }

    /// Get the vendor PQC key index saved in data vault on cold boot
    fn vendor_pqc_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.vendor_pqc_pk_index()
    }

    /// Get the owner public keys digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest384 {
        self.data_vault.fmc_tci().into()
    }

    // Get firmware fuse SVN
    fn fw_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fw_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        ICCM_RANGE
    }

    fn set_fw_extended_error(&mut self, err: u32) {
        self.soc_ifc.set_fw_extended_error(err);
    }

    fn pqc_key_type_fuse(&self) -> CaliptraResult<FwVerificationPqcKeyType> {
        let pqc_key_type =
            FwVerificationPqcKeyType::from_u8(self.soc_ifc.fuse_bank().pqc_key_type() as u8)
                .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_INVALID_PQC_KEY_TYPE_IN_FUSE)?;
        Ok(pqc_key_type)
    }

    fn dot_owner_pk_hash(&self) -> Option<&ImageDigest384> {
        if self.persistent_data.dot_owner_pk_hash.valid {
            Some(&self.persistent_data.dot_owner_pk_hash.owner_pk_hash)
        } else {
            None
        }
    }
}
