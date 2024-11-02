/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use crate::rom_env::RomEnv;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_common::keyids::KEY_ID_TMP;
use caliptra_drivers::*;
use caliptra_x509::Ecdsa384Signature;
use zeroize::Zeroize;

/// ECDSA-384 Signature Adapter
///
pub trait Ecdsa384SignatureAdapter {
    /// Convert to ECDSA Signature
    fn to_ecdsa(&self) -> Ecdsa384Signature;
}

impl Ecdsa384SignatureAdapter for Ecc384Signature {
    /// Convert to ECDSA Signatuure
    fn to_ecdsa(&self) -> Ecdsa384Signature {
        Ecdsa384Signature {
            r: (&self.r).into(),
            s: (&self.s).into(),
        }
    }
}

/// DICE  Layer Key Pair
#[derive(Debug, Zeroize)]
pub struct Ecc384KeyPair {
    /// Private Key KV Slot Id
    #[zeroize(skip)]
    pub priv_key: KeyId,

    /// Public Key
    pub pub_key: Ecc384PubKey,
}

/// DICE  Layer Key Pair
#[derive(Debug, Zeroize)]
pub struct MlDsaKeyPair {
    /// Key Pair Generation KV Slot Id
    #[zeroize(skip)]
    pub key_pair_seed: KeyId,

    /// Public Key
    pub pub_key: MlDsa87PubKey,
}

pub enum Crypto {}

impl Crypto {
    /// Calculate SHA1 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x5` - Digest
    #[inline(always)]
    pub fn sha1_digest(env: &mut RomEnv, data: &[u8]) -> CaliptraResult<Array4x5> {
        env.sha1.digest(data)
    }

    /// Calculate SHA2-256 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x8` - Digest
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha256_digest(env: &mut RomEnv, data: &[u8]) -> CaliptraResult<Array4x8> {
        env.sha256.digest(data)
    }

    /// Calculate SHA2-384 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x12` - Digest
    #[inline(always)]
    pub fn sha384_digest(env: &mut RomEnv, data: &[u8]) -> CaliptraResult<Array4x12> {
        env.sha384.digest(data)
    }

    /// Calculate HMAC-348
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key` - HMAC384 key slot
    /// * `data` - Input data to hash
    /// * `tag` - Key slot to store the tag
    #[inline(always)]
    pub fn hmac384_mac(
        env: &mut RomEnv,
        key: KeyId,
        data: &Hmac384Data,
        tag: KeyId,
    ) -> CaliptraResult<()> {
        env.hmac384.hmac(
            &KeyReadArgs::new(key).into(),
            data,
            &mut env.trng,
            KeyWriteArgs::new(
                tag,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en(),
            )
            .into(),
        )
    }

    /// Calculate HMAC-348 KDF
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key` - HMAC384 key slot
    /// * `label` - Input label
    /// * `context` - Input context
    /// * `output` - Key slot to store the output
    #[inline(always)]
    pub fn hmac384_kdf(
        env: &mut RomEnv,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
    ) -> CaliptraResult<()> {
        hmac384_kdf(
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
        )
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    #[inline(always)]
    pub fn ecc384_key_gen(
        env: &mut RomEnv,
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

    /// Sign the data using ECC Private Key.
    /// Verify the signature using the ECC Public Key.
    ///
    /// This routine calculates the digest of the `data`, signs the hash and returns the signature.
    /// This routine also verifies the signature using the public key.
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
    #[inline(always)]
    pub fn ecdsa384_sign_and_verify(
        env: &mut RomEnv,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let mut digest = Self::sha384_digest(env, data);
        let digest = okmutref(&mut digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        let result = env.ecc384.sign(&priv_key, pub_key, digest, &mut env.trng);
        digest.0.zeroize();
        result
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Value for hmac kdf.
    /// * `keypair_seed` - Key slot to store the keypair generation seed.
    ///
    /// # Returns
    ///
    /// * `MlDsa87PubKey` - Public key
    #[inline(always)]
    pub fn mldsa_key_gen(
        env: &mut RomEnv,
        cdi: KeyId,
        label: &[u8],
        keypair_seed: KeyId,
    ) -> CaliptraResult<MlDsa87PubKey> {
        // Generate the seed for key pair generation.
        // [TODO] Change this to hmac512_kdf.
        Crypto::hmac384_kdf(env, cdi, label, None, keypair_seed)?;

        // Generate the public key.
        let pub_key = env
            .mldsa
            .key_pair(&KeyReadArgs::new(keypair_seed), &mut env.trng)?;

        Ok(pub_key)
    }
}
