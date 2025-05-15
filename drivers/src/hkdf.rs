/*++

Licensed under the Apache-2.0 license.

File Name:

    hkdf.rs

Abstract:

    An HKDF implementation that is compliant with RFC 5869 and NIST SP 800-56Cr2 Section 5 (Two-Step Derivation).

--*/

use crate::{Array4x12, Array4x16, Hmac, HmacKey, HmacMode, HmacTag, Trng};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_error::{CaliptraError, CaliptraResult};

/// Calculate HKDF-Extract.
///
/// # Arguments
///
/// * `hmac` - HMAC context
/// * `ikm` - the input keying material or shared secret, sometimes called Z
/// * `salt` - salt used to strengthen the extraction
/// * `trng` - TRNG driver instance
/// * `prk` - Location to store the output PRK
/// * `mode` - HMAC Mode
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hkdf_extract(
    hmac: &mut Hmac,
    ikm: &[u8],
    salt: &[u8],
    trng: &mut Trng,
    prk: HmacTag,
    mode: HmacMode,
) -> CaliptraResult<()> {
    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::HMAC384_FAILURE)?
    }
    // NIST SP 800-56Cr2 says that salts less than the block length (1024 bits) should be
    // padded and larger than the block length should be hashed.
    // However, the hardware only supports HMAC keys up to the HMAC length (384 or 512 bits),
    // not the full block length.
    match mode {
        HmacMode::Hmac384 => {
            if salt.len() > 48 {
                Err(CaliptraError::DRIVER_HKDF_SALT_TOO_LONG)?;
            }
            let mut padded_salt = [0u8; 48];
            padded_salt[..salt.len()].copy_from_slice(salt);
            let padded_salt = Array4x12::from(padded_salt);
            let mut hmac_op = hmac.hmac_init((&padded_salt).into(), trng, prk, mode)?;
            hmac_op.update(ikm)?;
            hmac_op.finalize()
        }
        HmacMode::Hmac512 => {
            if salt.len() > 64 {
                return Err(CaliptraError::DRIVER_HKDF_SALT_TOO_LONG);
            }
            let mut padded_salt = [0u8; 64];
            padded_salt[..salt.len()].copy_from_slice(salt);
            let padded_salt = Array4x16::from(padded_salt);
            let mut hmac_op = hmac.hmac_init((&padded_salt).into(), trng, prk, mode)?;
            hmac_op.update(ikm)?;
            hmac_op.finalize()
        }
    }
}

/// Calculate HKDF-Expand.
///
/// # Arguments
///
/// * `hmac` - HMAC context
/// * `prk` - the pseudor random key material
/// * `label` - label used when expanding the key material. Sometimes called fixed info.
/// * `trng` - TRNG driver instance
/// * `okm` - Location to store the output key material
/// * `mode` - HMAC Mode
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn hkdf_expand(
    hmac: &mut Hmac,
    prk: HmacKey,
    label: &[u8],
    trng: &mut Trng,
    okm: HmacTag,
    mode: HmacMode,
) -> CaliptraResult<()> {
    #[cfg(feature = "fips-test-hooks")]
    unsafe {
        crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::HMAC384_FAILURE)?
    }
    let mut hmac_op = hmac.hmac_init(prk, trng, okm, mode)?;
    hmac_op.update(label)?;
    hmac_op.update(&[0x01])?;
    hmac_op.finalize()
}
