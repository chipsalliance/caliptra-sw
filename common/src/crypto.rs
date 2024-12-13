/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/
use caliptra_drivers::{
    Array4x12, Array4x8, CaliptraResult, Ecc384PubKey, Hmac, HmacMode, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs, Mldsa87PubKey, Sha256, Sha256Alg, Sha2_512_384, Trng,
};
use zeroize::Zeroize;

/// DICE Layer ECC Key Pair
#[derive(Debug, Zeroize)]
pub struct Ecc384KeyPair {
    /// Private Key KV Slot Id
    #[zeroize(skip)]
    pub priv_key: KeyId,

    /// Public Key
    pub pub_key: Ecc384PubKey,
}

/// DICE Layer MLDSA Key Pair
#[derive(Debug, Zeroize)]
pub struct MlDsaKeyPair {
    /// Key Pair Generation KV Slot Id
    #[zeroize(skip)]
    pub key_pair_seed: KeyId,

    /// Public Key
    pub pub_key: Mldsa87PubKey,
}

#[derive(Debug)]
pub enum PubKey<'a> {
    Ecc(&'a Ecc384PubKey),
    Mldsa(&'a Mldsa87PubKey),
}

/// Calculate SHA2-256 Digest
///
/// # Arguments
///
/// * `sha256` - SHA256 driver
/// * `data`   - Input data to hash
///
/// # Returns
///
/// * `Array4x8` - Digest
pub fn sha256_digest(sha256: &mut Sha256, data: &[u8]) -> CaliptraResult<Array4x8> {
    sha256.digest(data)
}

/// Calculate SHA2-384 Digest
///
/// # Arguments
///
/// * `sha2_512_384` - SHA2-512-384 driver
/// * `data` - Input data to hash
///
/// # Returns
///
/// * `Array4x12` - Digest
pub fn sha384_digest(sha2_512_384: &mut Sha2_512_384, data: &[u8]) -> CaliptraResult<Array4x12> {
    sha2_512_384.sha384_digest(data)
}

/// Calculate HMAC KDF
///
/// # Arguments
///
/// * `hmac` - HMAC driver
/// * `trng` - TRNG driver
/// * `key` - HMAC key slot
/// * `label` - Input label
/// * `context` - Input context
/// * `output` - Key slot to store the output
/// * `mode` - HMAC Mode
#[inline(always)]
pub fn hmac_kdf(
    hmac: &mut Hmac,
    trng: &mut Trng,
    key: KeyId,
    label: &[u8],
    context: Option<&[u8]>,
    output: KeyId,
    mode: HmacMode,
) -> CaliptraResult<()> {
    caliptra_drivers::hmac_kdf(
        hmac,
        KeyReadArgs::new(key).into(),
        label,
        context,
        trng,
        KeyWriteArgs::new(
            output,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en()
                .set_mldsa_key_gen_seed_en(),
        )
        .into(),
        mode,
    )
}
