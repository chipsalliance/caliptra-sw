// Licensed under the Apache-2.0 license

#[cfg(not(feature = "struct-aware"))]
use std::mem::size_of;

use caliptra_common::memory_layout::*;
use caliptra_drivers::*;
use caliptra_image_types::*;
use caliptra_image_verify::*;
use core::ops::Range;

#[cfg(feature = "struct-aware")]
const IMAGE_BUNDLE_SIZE: u32 = 131072;

/*
 * NOTE: Copied from image/verify/src/verifier.rs, unable to import.
 * - Possibly, because it is a required parameter for creating the object.
 * - But not an inherent issue, will likely implement/wrap an appropriate environment.
 *
 * TODO: Is this environment no-op tests, or sufficiently extensive?
 * - Ensures bundle is being fuzzed well (by offsets).
 */
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

impl Default for TestEnv {
    fn default() -> Self {
        TestEnv {
            digest: ImageDigest::default(),
            fmc_digest: ImageDigest::default(),
            // PATCHED
            verify_result: true,
            // PATCHED
            verify_lms_result: true,
            vendor_pub_key_digest: ImageDigest::default(),
            vendor_ecc_pub_key_revocation: VendorPubKeyRevocation::default(),
            vendor_lms_pub_key_revocation: 0,
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
        sig: &ImageEccSignature,
    ) -> CaliptraResult<Array4xN<12, 48>> {
        if self.verify_result {
            Ok(Array4x12::from(sig.r))
        } else {
            Ok(Array4x12::from(&[0xFF; 48]))
        }
    }

    fn lms_verify(
        &mut self,
        _digest: &ImageDigest,
        pub_key: &ImageLmsPublicKey,
        _sig: &ImageLmsSignature,
    ) -> CaliptraResult<HashValue<SHA192_DIGEST_WORD_SIZE>> {
        if self.verify_lms_result {
            Ok(HashValue::from(pub_key.digest))
        } else {
            Ok(HashValue::from(&[0xDEADBEEF; 6]))
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

    fn vendor_ecc_pub_key_idx_dv(&self) -> u32 {
        0
    }

    fn vendor_lms_pub_key_idx_dv(&self) -> u32 {
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
            start: ICCM_ORG,
            end: ICCM_ORG + ICCM_SIZE,
        }
    }

    fn lms_verify_enabled(&self) -> bool {
        true
    }
}

#[cfg(feature = "struct-aware")]
pub fn harness_structured(reset_reason: ResetReason, manifest: ImageManifest) {
    let test_env = TestEnv::default();
    let mut image_verifier = ImageVerifier::new(test_env);

    //println!("{:?}", fuzz_bundle);
    let _result = image_verifier.verify(&manifest, IMAGE_BUNDLE_SIZE, reset_reason);
    //println!("{:?}", _result);
}

#[cfg(not(feature = "struct-aware"))]
pub fn harness_unstructured(reset_reason: ResetReason, data: &[u8]) {
    let typed_fuzz_manifest: &ImageManifest;

    // The null-case is too hard to fuzz (better statically)
    // - Or, if we initialise with the `default()`, it's the test-case
    if data.len() < size_of::<ImageManifest>() {
        return;
    }

    unsafe {
        typed_fuzz_manifest = &*(data.as_ptr() as *const ImageManifest);
    }

    let test_env = TestEnv::default();
    let mut image_verifier = ImageVerifier::new(test_env);

    //println!("{:?}", fuzz_bundle);
    let _result = image_verifier.verify(
        typed_fuzz_manifest,
        data.len().try_into().unwrap(),
        reset_reason,
    );
    //println!("{:?}", _result);
}
