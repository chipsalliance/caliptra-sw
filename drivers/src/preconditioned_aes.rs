// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{cmac_kdf, Aes, AesGcmIv, AesKey, LEArray4x3, LEArray4x4, LEArray4x8, Trng};

use zerocopy::{FromBytes, IntoBytes};

pub struct PreconditionedAesEncryptionResult {
    pub iv: LEArray4x3,
    pub tag: LEArray4x4,
}

/// Implements Pre-conditioned AES Encrypt as described in
/// https://chipsalliance.github.io/Caliptra/ocp-lock/specification/HEAD/?content_ref=initializes+random+hpke+keypairs+for+each+supported+algorithm+and+assigns+handles+to+them+reported+via+enumerate_hpke_handles#sec:preconditioned-aes.
#[allow(clippy::too_many_arguments)]
pub fn preconditioned_aes_encrypt(
    aes: &mut Aes,
    trng: &mut Trng,
    key: AesKey,
    label: &[u8],
    aad: &[u8],
    salt: &[u8; 12],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> CaliptraResult<PreconditionedAesEncryptionResult> {
    let subkey = cmac_kdf(aes, key, label, Some(salt), 2)?;
    let subkey = subkey
        .as_bytes()
        .get(..32)
        .ok_or(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_ERROR)?;
    let truncated_subkey = <LEArray4x8>::ref_from_bytes(subkey)
        .map_err(|_| CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_ERROR)?;
    let (iv, tag) = aes.aes_256_gcm_encrypt(
        trng,
        AesGcmIv::Random,
        AesKey::Array(truncated_subkey),
        aad,
        plaintext,
        ciphertext,
        16,
    )?;

    Ok(PreconditionedAesEncryptionResult { iv, tag })
}

/// Implements Pre-conditioned AES Decrypt as described in
/// https://chipsalliance.github.io/Caliptra/ocp-lock/specification/HEAD/?content_ref=initializes+random+hpke+keypairs+for+each+supported+algorithm+and+assigns+handles+to+them+reported+via+enumerate_hpke_handles#sec:preconditioned-aes.
#[allow(clippy::too_many_arguments)]
pub fn preconditioned_aes_decrypt(
    aes: &mut Aes,
    trng: &mut Trng,
    key: AesKey,
    label: &[u8],
    aad: &[u8],
    salt: &[u8; 12],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    iv: &LEArray4x3,
    tag: &LEArray4x4,
) -> CaliptraResult<()> {
    let subkey = cmac_kdf(aes, key, label, Some(salt), 2)?;
    let subkey = subkey
        .as_bytes()
        .get(..32)
        .ok_or(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_DECRYPT_ERROR)?;
    let truncated_subkey = <LEArray4x8>::ref_from_bytes(subkey)
        .map_err(|_| CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_DECRYPT_ERROR)?;
    aes.aes_256_gcm_decrypt(
        trng,
        iv,
        AesKey::Array(truncated_subkey),
        aad,
        ciphertext,
        plaintext,
        tag,
    )
}
