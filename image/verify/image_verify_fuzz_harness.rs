// Licensed under the Apache-2.0 license

use std::mem::size_of;
use std::ptr::copy_nonoverlapping;

use caliptra_drivers::*;
use caliptra_image_types::*;
use caliptra_image_verify::*;
use core::ops::Range;

/*
 * NOTE: Copied from image/verify/src/verifier.rs, unable to import.
 * - Possibly, because it is a required parameter for creating the object.
 * - But not an inherent issue, will likely implement/wrap an appropriate environment.
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

// TODO: Should `data` be structure-aware? Then, it must implement `Arbitrary`
pub fn harness(reset_reason: ResetReason, data: &[u8]) {
    let typed_fuzz_manifest: &ImageManifest;

    // The null-case is too hard to fuzz (better statically)
    // - Or, if we initialise with the `default()`, it's the test-case
    if data.len() == 0 {
        return;
    }

    // At least `size_of::<ImageManifest>` of data required, or dereferences panic
    let mut buffer_size = size_of::<ImageManifest>();
    if data.len() > buffer_size {
        buffer_size = data.len();
    }

    // Note that uninitialised memory seems cleared with a given value
    let mut fuzz_bundle = Vec::<u8>::with_capacity(buffer_size);

    unsafe {
        // `copy_from_slice()` requires same-size, but `data` might be smaller
        copy_nonoverlapping(data.as_ptr(), fuzz_bundle.as_mut_ptr(), data.len());
        fuzz_bundle.set_len(buffer_size);

        typed_fuzz_manifest = &*(fuzz_bundle.as_ptr() as *const ImageManifest);
    }

    // TODO: Is this environment no-op tests, or sufficiently extensive?
    // - Ensures bundle is being fuzzed well (by offsets).
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
