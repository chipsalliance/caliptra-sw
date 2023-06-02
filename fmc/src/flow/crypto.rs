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
    Array4x12, Array4x5, Array4x8, CaliptraResult, Ecc384PrivKeyOut, Ecc384Seed, Hmac384Data,
    Hmac384Key, Hmac384Tag, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs,
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
        let mut usage = KeyUsage::default();
        usage.set_hmac_key(true);
        usage.set_ecc_key_gen_seed(true);
        let tag_args = Hmac384Tag::Key(KeyWriteArgs::new(tag, usage));

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

        let mut usage = KeyUsage::default();
        usage.set_ecc_private_key(true);

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(priv_key, usage));

        Ok(Ecc384KeyPair {
            priv_key,
            pub_key: env.ecc384.key_pair(seed, &Array4x12::default(), key_out)?,
        })
    }
}
