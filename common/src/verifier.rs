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

use caliptra_drivers::memory_layout::ICCM_RANGE;

/// ROM Verification Environemnt
pub struct FirmwareImageVerificationEnv<'a> {
    pub sha256: &'a mut Sha256,
    pub sha384: &'a mut Sha384,
    pub sha384_acc: &'a mut Sha384Acc,
    pub soc_ifc: &'a mut SocIfc,
    pub ecc384: &'a mut Ecc384,
    pub data_vault: &'a mut DataVault,
    pub pcr_bank: &'a mut PcrBank,
}

impl<'a> ImageVerificationEnv for &mut FirmwareImageVerificationEnv<'a> {
    /// Calculate Digest using SHA-384 Accelerator
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest> {
        loop {
            if let Some(mut txn) = self.sha384_acc.try_start_operation() {
                let mut digest = Array4x12::default();
                txn.digest(len, offset, false, &mut digest)?;
                return Ok(digest.0);
            }
        }
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
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

        self.ecc384.verify_r(&pub_key, &digest, &sig)
    }

    fn lms_verify(
        &mut self,
        digest: &ImageDigest,
        pub_key: &ImageLmsPublicKey,
        sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        let mut message = [0u8; SHA384_DIGEST_BYTE_SIZE];
        for i in 0..digest.len() {
            message[i * 4..][..4].copy_from_slice(&digest[i].to_be_bytes());
        }
        Lms::default().verify_lms_signature_cfi(self.sha256, &message, pub_key, sig)
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().vendor_pub_key_hash().into()
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
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
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

    /// Get the vendor key index saved in data vault on cold boot
    fn vendor_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.ecc_vendor_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FMC Key Manifest SVN
    fn fmc_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fmc_fuse_svn()
    }

    // Get Runtime fuse SVN
    fn runtime_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().runtime_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        ICCM_RANGE
    }

    fn lms_verify_enabled(&self) -> bool {
        self.soc_ifc.fuse_bank().lms_verify() == RomVerifyConfig::EcdsaAndLms
    }
}
