/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier.rs

Abstract:

    Image Verification support routines.

--*/

use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use caliptra_lib::*;

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
    type Image = ();

    /// Calculate Digest using SHA-384 Accelerator
    fn sha384_digest(
        &self,
        _image: Self::Image,
        offset: u32,
        len: u32,
    ) -> CaliptraResult<ImageDigest> {
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
        _image: Self::Image,
        digest: &ImageDigest,
        pub_key: &ImageEccPubKey,
        sig: &ImageEccSignature,
    ) -> CaliptraResult<bool> {
        // TODO: Remove following conversions after refactoring the driver ECC384PubKey
        // for use across targets
        let pub_key = Ecc384PubKey {
            x: pub_key.x().into(),
            y: pub_key.y().into(),
        };

        // TODO: Remove following conversions after refactoring the driver SHA384Digest
        // for use across targets
        let digest: Array4x12 = digest.into();

        // TODO: Remove following conversions after refactoring the driver ECC384Signature
        // for use across targets
        let sig = Ecc384Signature {
            r: sig.r().into(),
            s: sig.s().into(),
        };

        self.env.ecc384().map(|e| e.verify(&pub_key, &digest, &sig))
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self, _image: Self::Image) -> ImageDigest {
        self.env.fuse_bank().map(|f| f.vendor_pub_key_hash()).into()
    }

    /// Retrieve Vendor Public Key Revocation Bitmask
    fn vendor_pub_key_revocation(&self, _image: Self::Image) -> VendorPubKeyRevocation {
        self.env.fuse_bank().map(|f| f.vendor_pub_key_revocation())
    }

    /// Retrieve Owner Public Key Digest
    fn owner_pub_key_digest(&self, _image: Self::Image) -> ImageDigest {
        self.env.fuse_bank().map(|f| f.owner_pub_key_hash()).into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self, _image: Self::Image) -> bool {
        self.env.fuse_bank().map(|f| f.anti_rollback_disable())
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self, _image: Self::Image) -> Lifecycle {
        self.env.dev_state().map(|d| d.lifecycle())
    }
}
