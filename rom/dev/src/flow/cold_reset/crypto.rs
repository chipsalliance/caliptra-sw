/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use crate::rom_env::RomEnv;
use caliptra_drivers::*;
use caliptra_x509::Ecdsa384Signature;

/// ECDSA-384 Signature Adapter
///
/// TODO: This can be refactored and eliminated by X509 using `Ecc384Signature`
pub trait Ecdsa384SignatureAdapter {
    /// Convert to ECDSA Signatuure
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
#[derive(Debug)]
pub struct Ecc384KeyPair {
    /// Private Key
    pub priv_key: KeyId,

    /// Public Key
    pub pub_key: Ecc384PubKey,
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
    #[inline(always)]
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
    pub fn sha384_digest(env: &mut RomEnv, data: &[u8]) -> CaliptraResult<Array4x12> {
        env.sha384.digest(data)
    }

    /// Calculate HMAC-348
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key` - HMAC384 key
    /// * `data` - Input data to hash
    /// * `tag` - Key slot to store the tag
    ///
    /// # Returns
    ///
    /// * `KeyId` - Key Id inputted
    pub fn hmac384_mac(
        env: &mut RomEnv,
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
    /// * `env`   - ROM Environment
    /// * `seed` - Key slot to retrieve the seed from
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    pub fn ecc384_key_gen(
        env: &mut RomEnv,
        seed: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        // [TODO] Add Nonce to the ecc384_key_gen function
        let seed = Ecc384Seed::Key(KeyReadArgs::new(seed));

        let mut usage = KeyUsage::default();
        usage.set_ecc_private_key(true);

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(priv_key, usage));

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
        env: &mut RomEnv,
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
        env: &mut RomEnv,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<bool> {
        let digest = Self::sha384_digest(env, data);
        let digest = okref(&digest)?;
        env.ecc384.verify(pub_key, digest, sig)
    }
}
