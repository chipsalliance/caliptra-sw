/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use crate::rom_env::RomEnv;
use caliptra_common::{
    crypto::{self, Ecc384KeyPair, MlDsaKeyPair},
    keyids::KEY_ID_TMP,
};
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

    /// Calculate SHA2-512 Digest
    ///
    /// # Arguments
    ///
    /// * `env`   - ROM Environment
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Array4x16` - Digest
    #[inline(always)]
    #[allow(dead_code)]
    pub fn sha512_digest(env: &mut RomEnv, data: &[u8]) -> CaliptraResult<Array4x16> {
        env.sha2_512_384.sha512_digest(data)
    }

    /// Calculate HMAC
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key` - HMAC key slot
    /// * `data` - Input data to hash
    /// * `tag` - Key slot to store the tag
    /// * `mode` - HMAC Mode
    #[inline(always)]
    pub fn hmac_mac(
        env: &mut RomEnv,
        key: KeyId,
        data: &HmacData,
        tag: KeyId,
        mode: HmacMode,
    ) -> CaliptraResult<()> {
        env.hmac.hmac(
            &KeyReadArgs::new(key).into(),
            data,
            &mut env.trng,
            KeyWriteArgs::new(
                tag,
                KeyUsage::default()
                    .set_hmac_key_en()
                    .set_ecc_key_gen_seed_en()
                    .set_mldsa_key_gen_seed_en(),
            )
            .into(),
            mode,
        )
    }

    /// Calculate HMAC KDF
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
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
        hmac_kdf(
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

    /// Version of hmac_kdf() that takes a RomEnv.
    #[inline(always)]
    pub fn env_hmac_kdf(
        env: &mut RomEnv,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
        mode: HmacMode,
    ) -> CaliptraResult<()> {
        Crypto::hmac_kdf(
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
        let mut digest = crypto::sha384_digest(&mut env.sha2_512_384, data);
        let digest = okmutref(&mut digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        let result = env.ecc384.sign(&priv_key, pub_key, digest, &mut env.trng);
        digest.0.zeroize();
        result
    }

    /// Generate MLDSA Key Pair
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Value for hmac kdf.
    /// * `key_pair_seed` - Key slot to store the keypair generation seed.
    ///
    /// # Returns
    ///
    /// * `Mldsa87PubKey` - Public key
    #[inline(always)]
    pub fn mldsa_key_gen(
        env: &mut RomEnv,
        cdi: KeyId,
        label: &[u8],
        key_pair_seed: KeyId,
    ) -> CaliptraResult<MlDsaKeyPair> {
        // Generate the seed for key pair generation.
        Crypto::env_hmac_kdf(env, cdi, label, None, key_pair_seed, HmacMode::Hmac512)?;

        // Generate the public key.
        let pub_key = env
            .mldsa87
            .key_pair(&KeyReadArgs::new(key_pair_seed), &mut env.trng)?;

        Ok(MlDsaKeyPair {
            key_pair_seed,
            pub_key,
        })
    }
}
