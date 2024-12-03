/*++
Licensed under the Apache-2.0 license.
File Name:
    crypto.rs
Abstract:
    Crypto helper routines
--*/
use crate::fmc_env::FmcEnv;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{crypto::Ecc384KeyPair, keyids::KEY_ID_TMP};
use caliptra_drivers::{
    hmac_kdf, okref, Array4x12, Array4x5, Array4x8, CaliptraResult, Ecc384PrivKeyIn,
    Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Signature, HmacMode, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs, Sha256Alg,
};

pub enum Crypto {}

impl Crypto {
    /// Calculate SHA1 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - FMC Environment
    /// * `data`  - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x5` - Digest
    pub fn _sha1_digest(env: &mut FmcEnv, data: &[u8]) -> CaliptraResult<Array4x5> {
        env.sha1.digest(data)
    }

    /// Calculate SHA2-256 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - Fmc Environment
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x8` - Digest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(always)]
    pub fn sha256_digest(env: &mut FmcEnv, data: &[u8]) -> CaliptraResult<Array4x8> {
        env.sha256.digest(data)
    }

    /// Calculate SHA2-384 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - FMC Environment
    /// * `data`  - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Digest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha384_digest(env: &mut FmcEnv, data: &[u8]) -> CaliptraResult<Array4x12> {
        env.sha384.digest(data)
    }

    /// Calculate HMAC-384 KDF
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `key` - HMAC384 key slot
    /// * `label` - Input label
    /// * `context` - Input context
    /// * `output` - Key slot to store the output
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn hmac384_kdf(
        env: &mut FmcEnv,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
    ) -> CaliptraResult<()> {
        hmac_kdf(
            &mut env.hmac384,
            KeyReadArgs::new(key).into(),
            label,
            context,
            &mut env.trng,
            KeyWriteArgs::new(
                output,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
            HmacMode::Hmac384,
        )
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn ecc384_key_gen(
        env: &mut FmcEnv,
        cdi: KeyId,
        label: &[u8],
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        Crypto::hmac384_kdf(env, cdi, label, None, KEY_ID_TMP)?;

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(
            priv_key,
            KeyUsage::default().set_ecc_private_key_en(),
        ));

        let pub_key = env.ecc384.key_pair(
            &KeyReadArgs::new(KEY_ID_TMP).into(),
            &Array4x12::default(),
            &mut env.trng,
            key_out,
        );
        env.key_vault.erase_key(KEY_ID_TMP)?;

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
    /// * `env` - ROM Environment
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn ecdsa384_sign(
        env: &mut FmcEnv,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let digest = Self::sha384_digest(env, data);
        let digest = okref(&digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        env.ecc384.sign(&priv_key, pub_key, digest, &mut env.trng)
    }

    /// Verify the ECC Signature
    ///
    /// This routine calculates the digest and verifies the signature
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to hash
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    ///
    /// * `bool` - True on success, false otherwise
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn ecdsa384_verify(
        env: &mut FmcEnv,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        let digest = Self::sha384_digest(env, data);
        let digest = okref(&digest)?;
        env.ecc384.verify(pub_key, digest, sig)
    }
}
