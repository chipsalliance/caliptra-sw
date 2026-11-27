/*++

Licensed under the Apache-2.0 license.

File Name:

    loaded_image.rs

Abstract:

    File contains helpers for verifying firmware after it has been loaded.

--*/

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_drivers::{CaliptraResult, Sha2_512_384};
use caliptra_error::CaliptraError;
use caliptra_image_types::{ImageManifest, ImageTocEntry};

/// Verify the FMC and runtime images after they have been loaded into ICCM.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn verify_fmc_and_runtime(
    manifest: &ImageManifest,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<()> {
    verify_entry(
        &manifest.fmc,
        sha2_512_384,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH,
    )?;
    verify_runtime(manifest, sha2_512_384)
}

/// Verify the runtime image after it has been loaded into ICCM.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn verify_runtime(
    manifest: &ImageManifest,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<()> {
    verify_entry(
        &manifest.runtime,
        sha2_512_384,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
    )
}

/// Verify one loaded image entry against its manifest digest.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
fn verify_entry(
    entry: &ImageTocEntry,
    sha2_512_384: &mut Sha2_512_384,
    digest_failure: CaliptraError,
    digest_mismatch: CaliptraError,
) -> CaliptraResult<()> {
    // SAFETY: Image verification has already validated that this entry's load range is
    // entirely within ICCM and that the entry size is non-zero. ROM has just copied this
    // range into ICCM, so it is valid to read it as bytes for the post-copy digest check.
    let image =
        unsafe { core::slice::from_raw_parts(entry.load_addr as *const u8, entry.size as usize) };
    let actual = sha2_512_384
        .sha384_digest(image)
        .map_err(|_| digest_failure)?
        .0;

    if entry.digest != actual {
        Err(digest_mismatch)?;
    }
    caliptra_cfi_lib::cfi_assert_eq_12_words(&entry.digest, &actual);

    Ok(())
}
