/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/

use crate::rom_env::RomEnv;
use caliptra_lib::*;
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
            r: self.r.into(),
            s: self.s.into(),
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
    pub fn sha1_digest(env: &RomEnv, data: &[u8]) -> CaliptraResult<Array4x5> {
        let mut digest = Array4x5::default();
        env.sha1().map(|sha| sha.digest(data, &mut digest))?;
        Ok(digest)
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
    pub fn sha256_digest(env: &RomEnv, data: &[u8]) -> CaliptraResult<Array4x8> {
        let mut digest = Array4x8::default();
        env.sha256().map(|sha| sha.digest(data, &mut digest))?;
        Ok(digest)
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
    pub fn sha384_digest(env: &RomEnv, data: &[u8]) -> CaliptraResult<Array4x12> {
        let mut digest = Array4x12::default();
        env.sha384().map(|s| s.digest(data, &mut digest))?;
        Ok(digest)
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
        env: &RomEnv,
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
        env.hmac384().map(|h| h.hmac(key, data, tag_args))?;

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
        env: &RomEnv,
        seed: KeyId,
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        let seed = Ecc384Seed::Key(KeyReadArgs::new(seed));

        let mut usage = KeyUsage::default();
        usage.set_ecc_private_key(true);

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(priv_key, usage));

        Ok(Ecc384KeyPair {
            priv_key,
            pub_key: env.ecc384().map(|e| e.key_pair(seed, key_out))?,
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
        env: &RomEnv,
        priv_key: KeyId,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let digest = Self::sha384_digest(env, data)?;

        let data = Ecc384Data::Array4x12(&digest);

        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        env.ecc384().map(|ecc| ecc.sign(priv_key, data))
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
        env: &RomEnv,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<bool> {
        let digest = Self::sha384_digest(env, data)?;
        env.ecc384().map(|e| e.verify(pub_key, &digest, sig))
    }
}
