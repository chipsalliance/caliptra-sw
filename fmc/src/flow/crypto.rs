/*++
Licensed under the Apache-2.0 license.
File Name:
    crypto.rs
Abstract:
    Crypto helper routines
--*/
use crate::fmc_env::FmcEnv;
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::{
    crypto::{self, Ecc384KeyPair, MlDsaKeyPair},
    keyids::KEY_ID_TMP,
};
use caliptra_drivers::{
    okref, Array4x12, CaliptraResult, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey,
    Ecc384Result, Ecc384Signature, HmacMode, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
};

pub enum Crypto {}

impl Crypto {
    /// Version of hmac_kdf() that takes a FmcEnv.
    #[inline(always)]
    pub fn env_hmac_kdf(
        env: &mut FmcEnv,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
        mode: HmacMode,
    ) -> CaliptraResult<()> {
        crypto::hmac_kdf(
            &mut env.hmac,
            &mut env.trng,
            key,
            label,
            context,
            output,
            mode,
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
        Crypto::env_hmac_kdf(env, cdi, label, None, KEY_ID_TMP, HmacMode::Hmac512)?;

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
        let digest = crypto::sha384_digest(&mut env.sha2_512_384, data);
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
        let digest = crypto::sha384_digest(&mut env.sha2_512_384, data);
        let digest = okref(&digest)?;
        env.ecc384.verify(pub_key, digest, sig)
    }

    /// Generate MLDSA Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - FMC Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `key_pair_seed` - Key slot to store the keypair generation seed.
    ///
    /// # Returns
    ///
    /// * `MlDsaKeyPair` - Public Key and keypair generation seed
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(always)]
    pub fn mldsa_key_gen(
        env: &mut FmcEnv,
        cdi: KeyId,
        label: &[u8],
        key_pair_seed: KeyId,
    ) -> CaliptraResult<MlDsaKeyPair> {
        // Generate the seed for key pair generation.
        Crypto::env_hmac_kdf(env, cdi, label, None, key_pair_seed, HmacMode::Hmac512)?;

        // Generate the public key.
        let pub_key = env
            .mldsa
            .key_pair(&KeyReadArgs::new(key_pair_seed), &mut env.trng)?;

        Ok(MlDsaKeyPair {
            key_pair_seed,
            pub_key,
        })
    }
}
