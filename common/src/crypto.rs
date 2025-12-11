/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto.rs

Abstract:

    Crypto helper routines

--*/
use crate::keyids::KEY_ID_TMP;
use caliptra_drivers::{
    okmutref, okref, Aes, AesGcmIv, AesKey, Array4x12, CaliptraResult, Ecc384, Ecc384PrivKeyIn,
    Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Signature, Hmac, HmacData, HmacMode, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, LEArray4x3, LEArray4x4, LEArray4x8, Mldsa87,
    Mldsa87PubKey, Mldsa87Result, Mldsa87Seed, Mldsa87SignRnd, Mldsa87Signature, PersistentData,
    Sha2_512_384, Trng,
};
use caliptra_error::CaliptraError;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
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

pub const CMK_MAX_KEY_SIZE_BITS: usize = 512;
pub const UNENCRYPTED_CMK_SIZE_BYTES: usize = 80;

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct UnencryptedCmk {
    pub version: u16,
    pub length: u16,
    pub key_usage: u8,
    pub id: [u8; 3],
    pub usage_counter: u64,
    pub key_material: [u8; CMK_MAX_KEY_SIZE_BITS / 8],
}

impl UnencryptedCmk {
    #[allow(unused)]
    pub fn key_id(&self) -> u32 {
        self.id[0] as u32 | ((self.id[1] as u32) << 8) | ((self.id[2] as u32) << 16)
    }
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct EncryptedCmk {
    pub domain: u32,
    pub domain_metadata: [u8; 16],
    pub iv: LEArray4x3,
    pub ciphertext: [u8; UNENCRYPTED_CMK_SIZE_BYTES],
    pub gcm_tag: LEArray4x4,
}

pub struct Crypto {}

impl Crypto {
    /// Calculate HMAC
    ///
    /// # Arguments
    ///
    /// * `env` - ROM Environment
    /// * `key` - HMAC key slot
    /// * `data` - Input data to hash
    /// * `tag` - Key slot to store the tag
    /// * `mode` - HMAC Mode
    /// * `key_usage` - Key usage flags for the output key
    #[inline(always)]
    pub fn hmac_mac(
        hmac: &mut Hmac,
        trng: &mut Trng,
        key: KeyId,
        data: HmacData,
        tag: KeyId,
        mode: HmacMode,
        key_usage: KeyUsage,
    ) -> CaliptraResult<()> {
        hmac.hmac(
            KeyReadArgs::new(key).into(),
            data,
            trng,
            KeyWriteArgs::new(tag, key_usage).into(),
            mode,
        )
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
    /// * `key_usage` - Key usage flags for the output key
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn hmac_kdf(
        hmac: &mut Hmac,
        trng: &mut Trng,
        key: KeyId,
        label: &[u8],
        context: Option<&[u8]>,
        output: KeyId,
        mode: HmacMode,
        key_usage: KeyUsage,
    ) -> CaliptraResult<()> {
        caliptra_drivers::hmac_kdf(
            hmac,
            KeyReadArgs::new(key).into(),
            label,
            context,
            trng,
            KeyWriteArgs::new(output, key_usage).into(),
            mode,
        )
    }

    /// Generate ECC Key Pair
    ///
    /// # Arguments
    ///
    /// * `ecc384` - ECC384 driver
    /// * `hmac` - HMAC driver
    /// * `trng` - TRNG driver
    /// * `key_vault` - Caliptra key vault
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `priv_key` - Key slot to store the private key
    ///
    /// # Returns
    ///
    /// * `Ecc384KeyPair` - Private Key slot id and public key pairs
    #[inline(always)]
    pub fn ecc384_key_gen(
        ecc384: &mut Ecc384,
        hmac: &mut Hmac,
        trng: &mut Trng,
        key_vault: &mut KeyVault,
        cdi: KeyId,
        label: &[u8],
        priv_key: KeyId,
    ) -> CaliptraResult<Ecc384KeyPair> {
        Self::hmac_kdf(
            hmac,
            trng,
            cdi,
            label,
            None,
            KEY_ID_TMP,
            HmacMode::Hmac512,
            KeyUsage::default().set_ecc_key_gen_seed_en(),
        )?;

        let key_out = Ecc384PrivKeyOut::Key(KeyWriteArgs::new(
            priv_key,
            KeyUsage::default().set_ecc_private_key_en(),
        ));

        let pub_key = ecc384.key_pair(
            KeyReadArgs::new(KEY_ID_TMP).into(),
            &Array4x12::default(),
            trng,
            key_out,
        );
        key_vault.erase_key(KEY_ID_TMP)?;

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
    /// * `sha2_512_384` - SHA384 driver
    /// * `ecc384` - ECC384 driver
    /// * `trng` - TRNG driver
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[inline(always)]
    pub fn ecdsa384_sign(
        sha2_512_384: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        trng: &mut Trng,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let digest = sha2_512_384.sha384_digest(data);
        let digest = okref(&digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        ecc384.sign(priv_key, pub_key, digest, trng)
    }

    /// Verify the ECC Signature
    ///
    /// This routine calculates the digest and verifies the signature
    ///
    /// # Arguments
    ///
    /// * `sha2_512_384` - Sha2_512_384 driver
    /// * `ecc384` - ECC384 driver
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to hash
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    ///
    /// *  `Ecc384Result` - Ecc384Result::Success if the signature verification passed else an error code.
    #[inline(always)]
    pub fn ecdsa384_verify(
        sha2_512_384: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        pub_key: &Ecc384PubKey,
        data: &[u8],
        sig: &Ecc384Signature,
    ) -> CaliptraResult<Ecc384Result> {
        let digest = sha2_512_384.sha384_digest(data);
        let digest = okref(&digest)?;
        ecc384.verify(pub_key, digest, sig)
    }

    /// Sign the data using ECC Private Key.
    /// Verify the signature using the ECC Public Key.
    ///
    /// This routine calculates the digest of the `data`, signs the hash and returns the signature.
    /// This routine also verifies the signature using the public key.
    ///
    /// # Arguments
    ///
    /// * `sha2_512_384` - Sha2_512_384 driver
    /// * `ecc384` - ECC384 driver
    /// * `trng` - TRNG driver
    /// * `priv_key` - Key slot to retrieve the private key
    /// * `pub_key` - Public key to verify with
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// * `Ecc384Signature` - Signature
    #[inline(always)]
    pub fn ecdsa384_sign_and_verify(
        sha2_512_384: &mut Sha2_512_384,
        ecc384: &mut Ecc384,
        trng: &mut Trng,
        priv_key: KeyId,
        pub_key: &Ecc384PubKey,
        data: &[u8],
    ) -> CaliptraResult<Ecc384Signature> {
        let mut digest = sha2_512_384.sha384_digest(data);
        let digest = okmutref(&mut digest)?;
        let priv_key_args = KeyReadArgs::new(priv_key);
        let priv_key = Ecc384PrivKeyIn::Key(priv_key_args);
        let result = ecc384.sign(priv_key, pub_key, digest, trng);
        digest.0.zeroize();
        result
    }

    /// Generate MLDSA Key Pair
    ///
    /// # Arguments
    ///
    /// * `mldsa` - MLDSA87 driver
    /// * `hmac` - HMAC driver
    /// * `trng` - TRNG driver
    /// * `cdi` - Key slot to retrieve the CDI from
    /// * `label` - Diversification label
    /// * `key_pair_seed` - Key slot to store the keypair generation seed.
    ///
    /// # Returns
    ///
    /// * `MlDsaKeyPair` - Public Key and keypair generation seed
    #[inline(always)]
    pub fn mldsa87_key_gen(
        mldsa87: &mut Mldsa87,
        hmac: &mut Hmac,
        trng: &mut Trng,
        cdi: KeyId,
        label: &[u8],
        key_pair_seed: KeyId,
    ) -> CaliptraResult<MlDsaKeyPair> {
        // Generate the seed for key pair generation.
        Self::hmac_kdf(
            hmac,
            trng,
            cdi,
            label,
            None,
            key_pair_seed,
            HmacMode::Hmac512,
            KeyUsage::default().set_mldsa_key_gen_seed_en(),
        )?;

        // Generate the public key.
        let pub_key = mldsa87.key_pair(
            Mldsa87Seed::Key(KeyReadArgs::new(key_pair_seed)),
            trng,
            None,
        )?;

        Ok(MlDsaKeyPair {
            key_pair_seed,
            pub_key,
        })
    }

    /// Sign data using MLDSA Private Key
    ///
    /// # Arguments
    ///
    /// * `mldsa` - MLDSA87 driver
    /// * `trng` - TRNG driver
    /// * `key_pair_seed` - Key slot to retrieve the keypair generation seed
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to sign
    ///
    /// # Returns
    ///
    /// * `Mldsa87Signature` - Signature
    #[inline(always)]
    pub fn mldsa87_sign(
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        key_pair_seed: KeyId,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
    ) -> CaliptraResult<Mldsa87Signature> {
        mldsa87.sign_var(
            Mldsa87Seed::Key(KeyReadArgs::new(key_pair_seed)),
            pub_key,
            data,
            &Mldsa87SignRnd::default(),
            trng,
        )
    }

    /// Verify the MLDSA Signature
    ///
    /// # Arguments
    ///
    /// * `mldsa` - MLDSA87 driver
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to verify the signature on
    /// * `sig` - Signature to verify
    ///
    /// # Returns
    ///
    /// *  `Mldsa87Result` - Mldsa87Result::Success if the signature verification passed else an error code.
    #[inline(always)]
    pub fn mldsa87_verify(
        mldsa87: &mut Mldsa87,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
        sig: &Mldsa87Signature,
    ) -> CaliptraResult<Mldsa87Result> {
        mldsa87.verify_var(pub_key, data, sig)
    }

    /// Sign the data using MLDSA Private Key.
    /// Verify the signature using the MLDSA Public Key.
    ///
    /// # Arguments
    ///
    /// * `mldsa` - MLDSA87 driver
    /// * `trng` - TRNG driver
    /// * `key_pair_seed` - Key slot to retrieve the keypair generation seed
    /// * `pub_key` - Public key to verify the signature
    /// * `data` - Input data to sign
    ///
    /// # Returns
    ///
    /// * `Mldsa384Signature` - Signature
    #[inline(always)]
    pub fn mldsa87_sign_and_verify(
        mldsa87: &mut Mldsa87,
        trng: &mut Trng,
        key_pair_seed: KeyId,
        pub_key: &Mldsa87PubKey,
        data: &[u8],
    ) -> CaliptraResult<Mldsa87Signature> {
        mldsa87.sign_var(
            Mldsa87Seed::Key(KeyReadArgs::new(key_pair_seed)),
            pub_key,
            data,
            &Mldsa87SignRnd::default(),
            trng,
        )
    }

    pub fn get_cmb_aes_key(pdata: &PersistentData) -> (LEArray4x8, LEArray4x8) {
        (pdata.rom.cmb_aes_key_share0, pdata.rom.cmb_aes_key_share1)
    }

    /// Encrypt the Cryptographic Mailbox Key (CML) using the Key Encryption Key (KEK)
    ///
    /// # Arguments
    /// * `aes` - AES driver
    /// * `trng` - TRNG driver
    /// * `unencrypted_cmk` - Unencrypted CMK to encrypt
    /// * `kek_iv` - Initialization vector for the KEK
    /// * `kek` - Key Encrption Key (AES key)
    ///
    /// # Returns
    /// * `EncryptedCmk` - Encrypted CMK
    ///
    #[inline(always)]
    pub fn encrypt_cmk(
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_cmk: &UnencryptedCmk,
        kek_iv: LEArray4x3,
        kek: (LEArray4x8, LEArray4x8),
    ) -> CaliptraResult<EncryptedCmk> {
        let plaintext = unencrypted_cmk.as_bytes();
        let mut ciphertext = [0u8; UNENCRYPTED_CMK_SIZE_BYTES];
        // Encrypt the CMK using the KEK
        let (iv, gcm_tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesGcmIv::Array(&kek_iv),
            AesKey::Split(&kek.0, &kek.1),
            &[],
            plaintext,
            &mut ciphertext[..],
            16,
        )?;
        Ok(EncryptedCmk {
            domain: 0,
            domain_metadata: [0u8; 16],
            iv,
            ciphertext,
            gcm_tag,
        })
    }

    /// Decrypt the Cryptographic Mailbox Key (CMK) using the Key Encryption Key (KEK)
    ///
    /// # Arguments
    /// * `aes` - AES driver
    /// * `trng` - TRNG driver
    /// * `kek` - Key Encryption Key (AES key)
    /// * `encrypted_cmk` - Encrypted CMK to decrypt
    ///
    /// # Returns
    /// * `UnencryptedCmk` - Decrypted CMK
    ///
    #[inline(always)]
    pub fn decrypt_cmk(
        aes: &mut Aes,
        trng: &mut Trng,
        kek: (LEArray4x8, LEArray4x8),
        encrypted_cmk: &EncryptedCmk,
    ) -> CaliptraResult<UnencryptedCmk> {
        let ciphertext = &encrypted_cmk.ciphertext;
        let mut plaintext = [0u8; UNENCRYPTED_CMK_SIZE_BYTES];
        aes.aes_256_gcm_decrypt(
            trng,
            &encrypted_cmk.iv,
            AesKey::Split(&kek.0, &kek.1),
            &[],
            ciphertext,
            &mut plaintext,
            &encrypted_cmk.gcm_tag,
        )?;
        UnencryptedCmk::read_from_bytes(&plaintext)
            .map_err(|_| CaliptraError::CMB_HMAC_INVALID_DEC_CMK)
    }
}
