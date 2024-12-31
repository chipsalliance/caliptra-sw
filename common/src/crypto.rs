/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/
use caliptra_drivers::{
    CaliptraResult, Ecc384PubKey, Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
    Mldsa87PubKey, Trng,
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
