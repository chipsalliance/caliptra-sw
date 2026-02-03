// Licensed under the Apache-2.0 license

use caliptra_error::{CaliptraError, CaliptraResult};

use crate::{
    hmac_kdf, Aes, AesGcmIv, AesKey, Array4x16, Hmac, HmacKey, HmacMode, HmacTag, KeyReadArgs,
    KeyUsage, KeyVault, KeyWriteArgs, LEArray4x3, LEArray4x4, LEArray4x8, Trng,
};

use zerocopy::{FromBytes, IntoBytes};
use zeroize::Zeroize;

pub struct PreconditionedAesEncryptionResult {
    pub salt: LEArray4x3,
    pub iv: LEArray4x3,
    pub tag: LEArray4x4,
}

/// Implements Pre-conditioned AES Encrypt as described in
/// OCP LOCK version 1.0 RC2, Section "Preconditioned AES".
/// https://github.com/chipsalliance/Caliptra/issues/603 will align the specification with this
/// implementation.
///
/// NOTE: The `aes_key` parameter will be erased.
#[allow(clippy::too_many_arguments)]
pub fn preconditioned_aes_encrypt(
    aes: &mut Aes,
    hmac: &mut Hmac,
    trng: &mut Trng,
    kv: &mut KeyVault,
    key: HmacKey,
    aes_key: AesKey,
    label: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> CaliptraResult<PreconditionedAesEncryptionResult> {
    let salt: LEArray4x3 = {
        // Convert 48 bytes of entropy to 12.
        let seed = trng.generate()?;
        let seed = seed
            .as_bytes()
            .get(..12)
            .and_then(|seed| <[u32; 3]>::read_from_bytes(seed).ok())
            .ok_or(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_ERROR)?;
        LEArray4x3::new(seed)
    };

    let mut output_array = Array4x16::default();
    let tag = match aes_key {
        AesKey::KV(kv) => HmacTag::Key(KeyWriteArgs {
            id: kv.id,
            usage: KeyUsage::default().set_aes_key_en(),
        }),
        AesKey::Split(_, _) | AesKey::Array(_) => HmacTag::Array4x16(&mut output_array),
    };

    hmac_kdf(
        hmac,
        key,
        label,
        Some(salt.as_bytes()),
        trng,
        tag,
        HmacMode::Hmac512,
    )?;

    let subkey = match aes_key {
        AesKey::KV(kv) => AesKey::KV(KeyReadArgs { id: kv.id }),
        AesKey::Split(_, _) | AesKey::Array(_) => {
            AesKey::Array(
                // Truncate the 64 byte HmacTag to 32 bytes so we can use it as an AES-256 key
                output_array
                    .as_bytes()
                    .get(..32)
                    .and_then(|arr| <LEArray4x8>::ref_from_bytes(arr).ok())
                    .ok_or(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_ENCRYPT_ERROR)?,
            )
        }
    };

    let tag_size = 16;
    let res = aes.aes_256_gcm_encrypt(
        trng,
        AesGcmIv::Random,
        subkey,
        aad,
        plaintext,
        ciphertext,
        tag_size,
    );

    if let AesKey::KV(KeyReadArgs { id }) = aes_key {
        kv.erase_key(id)?;
    }
    output_array.zeroize();

    let (iv, tag) = res?;

    Ok(PreconditionedAesEncryptionResult { salt, iv, tag })
}

/// Implements Pre-conditioned AES Decrypt as described in
/// OCP LOCK version 1.0 RC2, Section "Preconditioned AES".
/// https://github.com/chipsalliance/Caliptra/issues/603 will align the specification with this
/// implementation.
///
/// NOTE: The `aes_key` parameter will be erased.
#[allow(clippy::too_many_arguments)]
pub fn preconditioned_aes_decrypt(
    aes: &mut Aes,
    hmac: &mut Hmac,
    trng: &mut Trng,
    kv: &mut KeyVault,
    key: HmacKey,
    aes_key: AesKey,
    label: &[u8],
    aad: &[u8],
    salt: &LEArray4x3,
    iv: &LEArray4x3,
    tag: &LEArray4x4,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> CaliptraResult<()> {
    let mut output_array = Array4x16::default();
    let hmac_tag = match aes_key {
        AesKey::KV(kv) => HmacTag::Key(KeyWriteArgs {
            id: kv.id,
            usage: KeyUsage::default().set_aes_key_en(),
        }),
        AesKey::Split(_, _) | AesKey::Array(_) => HmacTag::Array4x16(&mut output_array),
    };

    hmac_kdf(
        hmac,
        key,
        label,
        Some(salt.as_bytes()),
        trng,
        hmac_tag,
        HmacMode::Hmac512,
    )?;

    let subkey = match aes_key {
        AesKey::KV(kv) => AesKey::KV(KeyReadArgs { id: kv.id }),
        AesKey::Split(_, _) | AesKey::Array(_) => {
            AesKey::Array(
                // Truncate the 64 byte HmacTag to 32 bytes so we can use it as an AES-256 key
                output_array
                    .as_bytes()
                    .get(..32)
                    .and_then(|arr| <LEArray4x8>::ref_from_bytes(arr).ok())
                    .ok_or(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_AES_DECRYPT_ERROR)?,
            )
        }
    };

    let res = aes.aes_256_gcm_decrypt(trng, iv, subkey, aad, ciphertext, plaintext, tag);
    if let AesKey::KV(KeyReadArgs { id }) = aes_key {
        kv.erase_key(id)?;
    }
    output_array.zeroize();
    res
}
