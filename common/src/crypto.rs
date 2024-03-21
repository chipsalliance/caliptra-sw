/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use caliptra_drivers::{
    hmac384_kdf, okref, Array4x12, Array4x8, CaliptraResult, Ecc384, Ecc384PrivKeyIn,
    Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Signature, Hmac384, Hmac384Data, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Sha256, Sha256Alg, Sha384, Trng,
};
use zeroize::Zeroize;

use crate::keyids::KEY_ID_TMP;

/// DICE  Layer Key Pair
#[derive(Debug, Zeroize)]
pub struct Ecc384KeyPair {
    /// Private Key
    #[zeroize(skip)]
    pub priv_key: KeyId,

    /// Public Key
    pub pub_key: Ecc384PubKey,
}

pub enum Crypto {}

impl Crypto {
    /// Calculate SHA2-256 Digest
    ///
    /// # Arguments
    ///
    /// * `sha256` - SHA256 Driver
    /// * `data`   - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x8` - Digest
    #[inline(always)]
    pub fn sha256_digest(sha256: &mut Sha256, data: &[u8]) -> CaliptraResult<Array4x8> {
        sha256.digest(data)
    }

    /// Calculate SHA2-384 Digest
    ///
    /// # Arguments
    ///
    /// * `sha384' - SHA384 Driver
    /// * `data`   - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Digest
    #[inline(always)]
    pub fn sha384_digest(sha384: &mut Sha384, data: &[u8]) -> CaliptraResult<Array4x12> {
        sha384.digest(data)
    }

    /// Calculate HMAC-384 KDF
    ///
    /// # Arguments
    ///
    /// * `hmac384` - HMAC384 Driver
    /// * `trng` - TRNG
    /// * `key` - HMAC384 key slot
    /// * `label` - Input label
    /// * `context` - Input context
    /// * `output` - Key slot to store the output
    #[inline(always)]
    pub fn hmac384_kdf(
        hmac384: &mut Hmac384,
        trng: &mut Trng,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
    ) -> CaliptraResult<()> {
        hmac384_kdf(
            hmac384,
            KeyReadArgs::new(key).into(),
            label,
            context,
            trng,
            KeyWriteArgs::new(
                output,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
    }

    /// Calculate HMAC-384
    ///
    /// # Arguments
    ///
    /// * `hmac384` - HMAC384 Driver
    /// * `trng` - TRNG
    /// * `key` - HMAC384 key slot
    /// * `data` - Input data to hash
    /// * `tag` - Key slot to store the tag
    #[inline(always)]
    pub fn hmac384_mac(
        hmac384: &mut Hmac384,
        trng: &mut Trng,
        key: KeyId,
        data: &Hmac384Data,
        tag: KeyId,
    ) -> CaliptraResult<()> {
        hmac384.hmac(
            &KeyReadArgs::new(key).into(),
            data,
            trng,
            KeyWriteArgs::new(
                tag,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `hmac384` - HMAC384 Driver
    /// * `ecc384` - ECC384 Driver
    /// * `trng` - TRNG
    /// * `key_vault` - KeyVault
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    #[inline(always)]
    pub fn ecc384_key_gen(
        hmac384: &mut Hmac384,
        ecc384: &mut Ecc384,
        trng: &mut Trng,
        key_vault: &mut KeyVault,
        cdi: KeyId,
        label: &[u8],
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        Self::hmac384_kdf(hmac384, trng, cdi, label, None, KEY_ID_TMP)?;

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(
            priv_key,
            KeyUsage::default().set_ecc_private_key_en(),
        ));

        let pub_key = ecc384.key_pair(
            &KeyReadArgs::new(KEY_ID_TMP).into(),
            &Array4x12::default(),
            trng,
            key_out,
        );

        if KEY_ID_TMP != priv_key {
            key_vault.erase_key(KEY_ID_TMP)?;
        }

        Ok(Ecc384KeyPair {
            priv_key,
            pub_key: pub_key?,
        })
    }

    /// Sign data using ECC Private Key
    ///
    /// This routine calculates the digest of the `data` and signs the hash
    ///
    /// # Arguments
    ///
    /// * `sha384` - SHA384 Driver
    /// * `ecc384` - ECC384 Driver
    /// * `trng` - TRNG
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `pub_key` - Public Key corresponding to `priv_key`
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[inline(always)]
    pub fn ecdsa384_sign(
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        trng: &mut Trng,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let digest = Self::sha384_digest(sha384, data);
        let digest = okref(&digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        ecc384.sign(&priv_key, pub_key, digest, trng)
    }

    /// Verify the ECC Signature
    ///
    /// This routine calculates the digest and verifies the signature
    ///
    /// # Arguments
    ///
    /// * `sha384` - SHA384 Driver
    /// * `ecc384` - ECC384 Driver
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to hash
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    ///
    /// * `bool` - True on success, false otherwise
    #[inline(always)]
    pub fn ecdsa384_verify(
        sha384: &mut Sha384,
        ecc384: &mut Ecc384,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        let digest = Self::sha384_digest(sha384, data);
        let digest = okref(&digest)?;
        ecc384.verify(pub_key, digest, sig)
    }
}
