// Licensed under the Apache-2.0 license

use core::ops::Range;

use caliptra_common::cprintln;
use caliptra_drivers::CaliptraError;
use caliptra_drivers::CaliptraResult;
use caliptra_drivers::Ecc384Result;
use caliptra_drivers::Lifecycle;
use caliptra_drivers::LmsResult;
use caliptra_drivers::ResetReason;
use caliptra_drivers::VendorPubKeyRevocation;
use caliptra_image_types::ImageDigest;
use caliptra_image_types::ImageEccPubKey;
use caliptra_image_types::ImageEccSignature;
use caliptra_image_types::ImageLmsPublicKey;
use caliptra_image_types::ImageLmsSignature;
use caliptra_image_verify::ImageVerificationEnv;
use caliptra_image_verify::ImageVerifier;
use caliptra_kat::{Ecc384Kat, Hmac384Kat, Sha256Kat, Sha384AccKat, Sha384Kat};
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::{AsBytes, FromBytes};

use crate::Drivers;

pub struct FipsModule;

#[repr(C)]
#[derive(Clone, Debug, Default, AsBytes, FromBytes)]
pub struct VersionResponse {
    pub mode: u32,
    pub fips_rev: [u32; 3],
    pub name: [u8; 12],
}

impl VersionResponse {
    pub const NAME: [u8; 12] = *b"Caliptra RTM";
    pub const MODE: u32 = 0x46495053;

    pub fn new(_env: &Drivers) -> Self {
        Self {
            mode: Self::MODE,
            // Just return all zeroes for now.
            fips_rev: [1, 0, 0],
            name: Self::NAME,
        }
    }
    pub fn copy_to_mbox(&self, env: &mut Drivers) -> CaliptraResult<()> {
        let mbox = &mut env.mbox;
        mbox.write_response(self.as_bytes())
    }
}

/// Fips command handler.
impl FipsModule {
    pub fn version(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS Version");

        VersionResponse::new(env).copy_to_mbox(env)?;
        Ok(MboxStatusE::DataReady)
    }

    pub fn self_test(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        cprintln!("[rt] FIPS self test");
        Self::execute_kats(env)?;

        let mut verifier = ImageVerifier::new(TestEnv::default());
        // Verify Caliptra image loaded to ICCM by ROM using the manifest stored in DCCM.
        verifier.verify(&env.manifest, env.manifest.size, ResetReason::ColdReset)?;

        Ok(MboxStatusE::CmdComplete)
    }

    pub fn shutdown(env: &mut Drivers) -> CaliptraResult<MboxStatusE> {
        Self::zeroize(env);
        env.mbox.set_status(MboxStatusE::CmdComplete);

        Err(CaliptraError::RUNTIME_SHUTDOWN)
    }

    /// Clear data structures in DCCM.  
    fn zeroize(env: &mut Drivers) {
        env.regions.zeroize();
    }

    /// Execute KAT for cryptographic algorithms implemented in H/W.
    fn execute_kats(env: &mut Drivers) -> CaliptraResult<()> {
        cprintln!("[kat] Executing SHA2-256 Engine KAT");
        Sha256Kat::default().execute(&mut env.sha256)?;

        cprintln!("[kat] Executing SHA2-384 Engine KAT");
        Sha384Kat::default().execute(&mut env.sha384)?;

        cprintln!("[kat] Executing SHA2-384 Accelerator KAT");
        Sha384AccKat::default().execute(&mut env.sha384_acc)?;

        cprintln!("[kat] Executing ECC-384 Engine KAT");
        Ecc384Kat::default().execute(&mut env.ecc384, &mut env.trng)?;

        cprintln!("[kat] Executing HMAC-384 Engine KAT");
        Hmac384Kat::default().execute(&mut env.hmac384, &mut env.trng)?;

        Ok(())
    }
}

struct TestEnv {
    digest: ImageDigest,
    fmc_digest: ImageDigest,
    verify_result: bool,
    verify_lms_result: bool,
    vendor_pub_key_digest: ImageDigest,
    vendor_ecc_pub_key_revocation: VendorPubKeyRevocation,
    vendor_lms_pub_key_revocation: u32,
    owner_pub_key_digest: ImageDigest,
    lifecycle: Lifecycle,
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
    ) -> CaliptraResult<Ecc384Result> {
        if self.verify_result {
            Ok(Ecc384Result::Success)
        } else {
            Ok(Ecc384Result::SigVerifyFailed)
        }
    }

    fn lms_verify(
        &mut self,
        _digest: &ImageDigest,
        _pub_key: &ImageLmsPublicKey,
        _sig: &ImageLmsSignature,
    ) -> CaliptraResult<LmsResult> {
        if self.verify_lms_result {
            Ok(LmsResult::Success)
        } else {
            Ok(LmsResult::SigVerifyFailed)
        }
    }

    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.vendor_pub_key_digest
    }

    fn vendor_ecc_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.vendor_ecc_pub_key_revocation
    }

    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.vendor_lms_pub_key_revocation
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

    fn fmc_fuse_svn(&self) -> u32 {
        0
    }

    fn runtime_fuse_svn(&self) -> u32 {
        0
    }

    fn iccm_range(&self) -> Range<u32> {
        Range {
            start: 0x40000000,
            end: 0x40000000 + (128 * 1024),
        }
    }

    fn lms_verify_enabled(&self) -> bool {
        true
    }
}

impl Default for TestEnv {
    fn default() -> Self {
        TestEnv {
            digest: ImageDigest::default(),
            fmc_digest: ImageDigest::default(),
            verify_result: false,
            verify_lms_result: false,
            vendor_pub_key_digest: ImageDigest::default(),
            vendor_ecc_pub_key_revocation: VendorPubKeyRevocation::default(),
            vendor_lms_pub_key_revocation: 0,
            owner_pub_key_digest: ImageDigest::default(),
            lifecycle: Lifecycle::Unprovisioned,
        }
    }
}
