/*++
Licensed under the Apache-2.0 license.
File Name:
    crypto.rs
Abstract:
    Crypto helper routines
--*/
use crate::fmc_env::FmcEnv;
use caliptra_common::crypto::Ecc384KeyPair;
use caliptra_drivers::{
    okref, Array4x12, Array4x5, Array4x8, CaliptraResult, Ecc384PrivKeyIn, Ecc384PrivKeyOut,
    Ecc384PubKey, Ecc384Seed, Ecc384Signature, Hmac384Data, Hmac384Key, Hmac384Tag, KeyId,
    KeyReadArgs, KeyUsage, KeyWriteArgs,
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
    pub fn sha384_digest(env: &mut FmcEnv, data: &[u8]) -> CaliptraResult<Array4x12> {
        env.sha384.digest(data)
    }

    /// Calculate HMAC-384
    ///
    /// # Arguments
    ///
    /// * `env`  - FMC Environment
    /// * `key`  - HMAC384 key
    /// * `data` - Input data to hash
    /// * `tag`  - Key slot to store the tag
    ///
    /// # Returns
    ///
    /// * `KeyId` - Key Id inputted
    pub fn hmac384_mac(
        env: &mut FmcEnv,
        key: Hmac384Key,
        data: Hmac384Data,
        tag: KeyId,
    ) -> CaliptraResult<KeyId> {
        // Tag
        let tag_args = Hmac384Tag::Key(KeyWriteArgs::new(
            tag,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_key_gen_seed_en(),
        ));

        // Calculate the CDI
        env.hmac384.hmac(key, data, tag_args)?;

        Ok(tag)
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `env`      - FMC Environment
    /// * `seed`     - Key slot to retrieve the seed from
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    pub fn ecc384_key_gen(
        env: &mut FmcEnv,
        seed: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        let seed = Ecc384Seed::Key(KeyReadArgs::new(seed));

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(
            priv_key,
            KeyUsage::default().set_ecc_private_key_en(),
        ));

        Ok(Ecc384KeyPair {
            priv_key,
            pub_key: env.ecc384.key_pair(seed, &Array4x12::default(), key_out)?,
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
    pub fn ecdsa384_sign(
        env: &mut FmcEnv,
        priv_key: KeyId,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let digest = Self::sha384_digest(env, data);
        let digest = okref(&digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        env.ecc384.sign(priv_key, digest)
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
    pub fn ecdsa384_verify(
        env: &mut FmcEnv,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<bool> {
        let digest = Self::sha384_digest(env, data);
        let digest = okref(&digest)?;
        env.ecc384.verify(pub_key, digest, sig)
    }
}
