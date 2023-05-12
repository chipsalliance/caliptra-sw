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

use crate::rom_env::RomEnv;

/// ROM Verification Environemnt
pub(crate) struct RomImageVerificationEnv<'a> {
    env: &'a RomEnv,
}

impl<'a> RomImageVerificationEnv<'a> {
    /// Create and instance `RomImageVerificationEnv`
    pub fn new(env: &'a RomEnv) -> Self {
        Self { env }
    }
}

impl<'a> ImageVerificationEnv for RomImageVerificationEnv<'a> {
    /// Calculate Digest using SHA-384 Accelerator
    fn sha384_digest(&self, offset: u32, len: u32) -> CaliptraResult<ImageDigest> {
        loop {
            if let Some(mut txn) = self.env.sha384_acc().map(|s| s.try_start_operation()) {
                let mut digest = Array4x12::default();
                txn.digest(len, offset, false, &mut digest)?;
                return Ok(digest.0);
            }
        }
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &self,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<bool> {
        // TODO: Remove following conversions after refactoring the driver ECC384PubKey
        // for use across targets
        let pub_key = Ecc384PubKey {
            x: pub_key.x.into(),
            y: pub_key.y.into(),
        };

        // TODO: Remove following conversions after refactoring the driver SHA384Digest
        // for use across targets
        let digest: Array4x12 = digest.into();

        // TODO: Remove following conversions after refactoring the driver ECC384Signature
        // for use across targets
        let sig = Ecc384Signature {
            r: sig.r.into(),
            s: sig.s.into(),
        };

        self.env.ecc384().map(|e| e.verify(&pub_key, &digest, &sig))
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.env
            .soc_ifc()
            .map(|f| f.fuse_bank().vendor_pub_key_hash())
            .into()
    }

    /// Retrieve Vendor Public Key Revocation Bitmask
    fn vendor_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.env
            .soc_ifc()
            .map(|f| f.fuse_bank().vendor_pub_key_revocation())
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
        self.env
            .soc_ifc()
            .map(|f| f.fuse_bank().owner_pub_key_hash())
            .into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.env
            .soc_ifc()
            .map(|f| f.fuse_bank().anti_rollback_disable())
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.env.soc_ifc().map(|d| d.lifecycle())
    }

    /// Get the vendor key index saved in data vault on cold boot
    fn vendor_pub_key_idx_dv(&self) -> u32 {
        self.env.data_vault().map(|dv| dv.vendor_pk_index())
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest {
        self.env.data_vault().map(|dv| dv.owner_pk_hash()).into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest {
        self.env.data_vault().map(|dv| dv.fmc_tci()).into()
    }

    // Get Fuse FMC Key Manifest SVN
    fn fmc_svn(&self) -> u32 {
        self.env.soc_ifc().map(|f| f.fuse_bank().fmc_svn())
    }

    // Get Runtime fuse SVN
    fn runtime_svn(&self) -> u32 {
        self.env.soc_ifc().map(|f| f.fuse_bank().runtime_svn())
    }

    fn iccm_range(&self) -> Range<u32> {
        self.env.iccm_range()
    }
}
