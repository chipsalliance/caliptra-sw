/*++

Licensed under the Apache-2.0 license.

File Name:

    cryptographic_mailbox.rs

Abstract:

    File contains exports for the Cryptographic Mailbox API commands.

--*/

use crate::{mutrefbytes, Drivers};
use arrayvec::ArrayVec;
use bitfield::bitfield;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::{
    crypto::{Crypto, EncryptedCmk, UnencryptedCmk, UNENCRYPTED_CMK_SIZE_BYTES},
    hmac_cm::hmac,
    keyids::{KEY_ID_STABLE_IDEV, KEY_ID_STABLE_LDEV},
    mailbox_api::{
        CmAesDecryptInitReq, CmAesDecryptUpdateReq, CmAesEncryptInitReq, CmAesEncryptInitResp,
        CmAesEncryptUpdateReq, CmAesGcmDecryptDmaReq, CmAesGcmDecryptDmaResp,
        CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptInitReq,
        CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq, CmAesGcmDecryptUpdateResp,
        CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp, CmAesGcmEncryptInitReq,
        CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp,
        CmAesGcmSpdmDecryptInitReq, CmAesGcmSpdmDecryptInitResp, CmAesGcmSpdmEncryptInitReq,
        CmAesGcmSpdmEncryptInitResp, CmAesMode, CmAesResp, CmDeleteReq, CmDeriveStableKeyReq,
        CmDeriveStableKeyResp, CmEcdhFinishReq, CmEcdhFinishResp, CmEcdhGenerateReq,
        CmEcdhGenerateResp, CmEcdsaPublicKeyReq, CmEcdsaPublicKeyResp, CmEcdsaSignReq,
        CmEcdsaSignResp, CmEcdsaVerifyReq, CmHashAlgorithm, CmHkdfExpandReq, CmHkdfExpandResp,
        CmHkdfExtractReq, CmHkdfExtractResp, CmHmacKdfCounterReq, CmHmacKdfCounterResp,
        CmImportReq, CmImportResp, CmKeyUsage, CmMldsaPublicKeyReq, CmMldsaPublicKeyResp,
        CmMldsaSignReq, CmMldsaSignResp, CmMldsaVerifyReq, CmRandomGenerateReq,
        CmRandomGenerateResp, CmRandomStirReq, CmShaFinalResp, CmShaInitReq, CmShaInitResp,
        CmShaUpdateReq, CmStableKeyType, CmStatusResp, Cmk as MailboxCmk, MailboxRespHeader,
        MailboxRespHeaderVarSize, ResponseVarSize, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE,
        CMB_ECDH_CONTEXT_SIZE, CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_SHA_CONTEXT_SIZE,
        CMK_MAX_KEY_SIZE_BITS, CMK_SIZE_BYTES, CM_STABLE_KEY_INFO_SIZE_BYTES, MAX_CMB_DATA_SIZE,
    },
};
use caliptra_drivers::{
    cmac_kdf, hkdf_expand, hkdf_extract, hmac_kdf,
    sha2_512_384::{Sha2DigestOpTrait, SHA512_BLOCK_BYTE_SIZE, SHA512_HASH_SIZE},
    Aes, AesContext, AesDmaMode, AesGcmContext, AesGcmIv, AesKey, AesOperation, Array4x12,
    Array4x16, AxiAddr, BootMode, CaliptraResult, DmaRecovery, Ecc384PrivKeyIn, Ecc384PrivKeyOut,
    Ecc384PubKey, Ecc384Result, Ecc384Seed, Ecc384Signature, HmacMode, KeyReadArgs, LEArray4x1157,
    LEArray4x3, LEArray4x4, LEArray4x8, Mldsa87Result, Mldsa87Seed, PersistentDataAccessor,
    Sha2_512_384, Trng, AES_BLOCK_SIZE_BYTES, AES_CONTEXT_SIZE_BYTES, AES_GCM_CONTEXT_SIZE_BYTES,
    MAX_SEED_WORDS,
};
use caliptra_error::CaliptraError;
use caliptra_image_types::{
    ECC384_SCALAR_BYTE_SIZE, SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE,
};
use constant_time_eq::constant_time_eq;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

pub const GCM_MAX_KEY_USES: u64 = (1 << 32) - 1;
pub const KEY_USAGE_MAX: usize = 256;
pub const MLDSA_SEED_SIZE: usize = 32;

// We have 24 bits for the key ID.
const MAX_KEY_ID: u32 = 0xffffff;

bitfield! {
    #[derive(Clone, Copy)]
    pub struct SpdmFlags(u32);
    pub version, set_image_version: 7, 0;
    pub counter_big_endian, set_counter_big_endian: 8, 8;
}

/// Holds data for the cryptographic mailbox system.
#[derive(Default)]
pub struct CmStorage {
    initialized: bool,
    // Usage counters for individual GCM keys.
    counters: ArrayVec<KeyUsageInfo, KEY_USAGE_MAX>,
    // 1-up counter for KEK GCM IV
    kek_next_iv: u128,
    // KEK split into two key shares
    kek: (LEArray4x8, LEArray4x8),
    // 1-up counter for context GCM IV
    context_next_iv: u128,
    // key for encrypting contexts
    context_key: (LEArray4x8, LEArray4x8),
}

impl CmStorage {
    pub fn new() -> Self {
        Self {
            kek: (LEArray4x8::default(), LEArray4x8::default()),
            context_key: (LEArray4x8::default(), LEArray4x8::default()),
            ..Default::default()
        }
    }

    /// Initialize the cryptographic mailbox storage key and IV.
    /// This is done after the TRNG is initialized and CFI is configured.
    pub fn init(&mut self, pdata: &PersistentDataAccessor, trng: &mut Trng) -> CaliptraResult<()> {
        let kek_random_iv = trng.generate4()?;
        // we mask off the top bit so that we always have at least 2^95 usages left.
        self.context_next_iv = (((kek_random_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((kek_random_iv.1 as u128) << 32)
            | (kek_random_iv.2 as u128);
        self.kek = Crypto::get_cmb_aes_key(pdata.get());

        let context_key_share0: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        let context_key_share1: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        // we mask off the top bit so that we always have at least 2^95 usages left.
        let context_random_iv = trng.generate4()?;
        self.context_next_iv = (((context_random_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((context_random_iv.1 as u128) << 32)
            | (context_random_iv.2 as u128);
        self.context_key = (
            transmute!(context_key_share0),
            transmute!(context_key_share1),
        );

        self.initialized = true;
        Ok(())
    }

    fn increment_counter(&mut self, cmk: &UnencryptedCmk) -> CaliptraResult<u64> {
        match self
            .counters
            .binary_search_by_key(&cmk.key_id(), |k| k.key_id)
        {
            Ok(idx) => Ok(self.counters[idx].increment()),
            Err(_) => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }

    /// Inserts a new counter (with 0 usage) and returns the new key id.
    pub fn add_counter(&mut self) -> CaliptraResult<[u8; 3]> {
        if self.counters.is_full() {
            return Err(CaliptraError::RUNTIME_CMB_KEY_USAGE_STORAGE_FULL);
        }
        let mut key_id =
            (self.counters.last().map(|last| last.key_id).unwrap_or(0) + 1) % MAX_KEY_ID;

        // normally we could just append to the end of the list, but if keys have been deleted,
        // we could potentially wraparound the 24-bit key id space, so we have to check
        loop {
            match self.counters.binary_search_by_key(&key_id, |k| k.key_id) {
                Ok(_) => {
                    // key_id already exists, increment and try again
                    // this only happens where there has been wraparound due to many keys imported and deleted
                    key_id = (key_id + 1) % MAX_KEY_ID;
                    continue;
                }
                Err(index) => {
                    let key_usage_info = KeyUsageInfo { key_id, counter: 0 };
                    self.counters.insert(index, key_usage_info);
                    return Ok(key_id.to_le_bytes()[0..3].try_into().unwrap());
                }
            }
        }
    }

    /// Deletes the counter for the given key id, if it exists.
    pub fn delete_counter(&mut self, key_id: u32) -> CaliptraResult<()> {
        match self.counters.binary_search_by_key(&key_id, |k| k.key_id) {
            Ok(idx) => {
                self.counters.remove(idx);
                Ok(())
            }
            Err(_) => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }

    /// Deletes all counters.
    pub fn clear_counters(&mut self) {
        self.counters.clear();
    }

    fn encrypt_cmk(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_cmk: &UnencryptedCmk,
    ) -> CaliptraResult<EncryptedCmk> {
        let kek_iv: [u32; 4] = transmute!(self.kek_next_iv);
        let kek_iv: [u32; 3] = kek_iv[..3].try_into().unwrap();
        self.kek_next_iv += 1;

        Crypto::encrypt_cmk(aes, trng, unencrypted_cmk, kek_iv.into(), self.kek)
    }

    fn decrypt_cmk(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_cmk: &EncryptedCmk,
    ) -> CaliptraResult<UnencryptedCmk> {
        Crypto::decrypt_cmk(aes, trng, self.kek, encrypted_cmk)
    }

    fn encrypt_aes_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_context: &AesContext,
    ) -> CaliptraResult<EncryptedAesContext> {
        let context_iv: [u32; 4] = transmute!(self.context_next_iv);
        let context_iv: [u32; 3] = context_iv[..3].try_into().unwrap();
        let context_iv: LEArray4x3 = context_iv.into();
        self.context_next_iv += 1;

        let mut ciphertext = [0u8; AES_CONTEXT_SIZE_BYTES];
        // Encrypt the context using the context key
        let (iv, tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesGcmIv::Array(&context_iv),
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            unencrypted_context.as_bytes(),
            &mut ciphertext[..],
            16,
        )?;
        Ok(EncryptedAesContext {
            iv,
            tag,
            ciphertext,
        })
    }

    fn decrypt_aes_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_context: &EncryptedAesContext,
    ) -> CaliptraResult<AesContext> {
        let ciphertext = &encrypted_context.ciphertext;
        let mut plaintext = [0u8; AES_CONTEXT_SIZE_BYTES];
        aes.aes_256_gcm_decrypt(
            trng,
            &encrypted_context.iv,
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            ciphertext,
            &mut plaintext,
            &encrypted_context.tag,
        )?;
        Ok(transmute!(plaintext))
    }

    fn encrypt_aes_gcm_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_context: &AesGcmContext,
    ) -> CaliptraResult<EncryptedAesGcmContext> {
        let context_iv: [u32; 4] = transmute!(self.context_next_iv);
        let context_iv: [u32; 3] = context_iv[..3].try_into().unwrap();
        let context_iv: LEArray4x3 = context_iv.into();
        self.context_next_iv += 1;

        let mut ciphertext = [0u8; AES_GCM_CONTEXT_SIZE_BYTES];
        // Encrypt the context using the context key
        let (iv, tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesGcmIv::Array(&context_iv),
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            unencrypted_context.as_bytes(),
            &mut ciphertext[..],
            16,
        )?;
        Ok(EncryptedAesGcmContext {
            iv,
            tag,
            ciphertext,
        })
    }

    fn decrypt_aes_gcm_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_context: &EncryptedAesGcmContext,
    ) -> CaliptraResult<AesGcmContext> {
        let ciphertext = &encrypted_context.ciphertext;
        let mut plaintext = [0u8; AES_GCM_CONTEXT_SIZE_BYTES];
        aes.aes_256_gcm_decrypt(
            trng,
            &encrypted_context.iv,
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            ciphertext,
            &mut plaintext,
            &encrypted_context.tag,
        )?;
        Ok(transmute!(plaintext))
    }

    fn encrypt_ecdh_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_context: &[u8; CMB_ECDH_CONTEXT_SIZE],
    ) -> CaliptraResult<EncryptedEcdhContext> {
        let context_iv: [u32; 4] = transmute!(self.context_next_iv);
        let context_iv: [u32; 3] = context_iv[..3].try_into().unwrap();
        let context_iv: LEArray4x3 = context_iv.into();
        self.context_next_iv += 1;

        let mut ciphertext = [0u8; CMB_ECDH_CONTEXT_SIZE];
        // Encrypt the context using the context key
        let (iv, tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesGcmIv::Array(&context_iv),
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            unencrypted_context,
            &mut ciphertext[..],
            16,
        )?;
        Ok(EncryptedEcdhContext {
            iv,
            tag,
            ciphertext,
        })
    }

    fn decrypt_ecdh_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_context: &EncryptedEcdhContext,
    ) -> CaliptraResult<[u8; CMB_ECDH_CONTEXT_SIZE]> {
        let ciphertext = &encrypted_context.ciphertext;
        let mut plaintext = [0u8; CMB_ECDH_CONTEXT_SIZE];
        aes.aes_256_gcm_decrypt(
            trng,
            &encrypted_context.iv,
            AesKey::Split(&self.context_key.0, &self.context_key.1),
            &[],
            ciphertext,
            &mut plaintext,
            &encrypted_context.tag,
        )?;
        Ok(plaintext)
    }
}

#[derive(Default)]
struct KeyUsageInfo {
    key_id: u32,
    #[allow(unused)]
    counter: u64,
}

impl KeyUsageInfo {
    fn increment(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct ShaContext {
    pub length: u32,
    pub hash_algorithm: u32,
    pub input_buffer: [u8; SHA512_BLOCK_BYTE_SIZE],
    pub intermediate_hash: [u8; SHA512_HASH_SIZE],
}

impl Default for ShaContext {
    fn default() -> Self {
        ShaContext {
            input_buffer: [0u8; SHA512_BLOCK_BYTE_SIZE],
            intermediate_hash: [0u8; SHA512_HASH_SIZE],
            length: 0,
            hash_algorithm: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct EncryptedAesContext {
    pub iv: LEArray4x3,
    pub tag: LEArray4x4,
    pub ciphertext: [u8; AES_CONTEXT_SIZE_BYTES],
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct EncryptedAesGcmContext {
    pub iv: LEArray4x3,
    pub tag: LEArray4x4,
    pub ciphertext: [u8; AES_GCM_CONTEXT_SIZE_BYTES],
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct EncryptedEcdhContext {
    pub iv: LEArray4x3,
    pub tag: LEArray4x4,
    pub ciphertext: [u8; CMB_ECDH_CONTEXT_SIZE],
}

const _: () = assert!(core::mem::size_of::<UnencryptedCmk>() == UNENCRYPTED_CMK_SIZE_BYTES);
const _: () = assert!(core::mem::size_of::<EncryptedCmk>() == CMK_SIZE_BYTES);
const _: () = assert!(core::mem::size_of::<ShaContext>() == CMB_SHA_CONTEXT_SIZE);
const _: () =
    assert!(core::mem::size_of::<EncryptedAesGcmContext>() == CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE);

const _: () =
    assert!(core::mem::size_of::<EncryptedEcdhContext>() == CMB_ECDH_ENCRYPTED_CONTEXT_SIZE);

pub(crate) struct Commands {}

impl Commands {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn status(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        let len = drivers.cryptographic_mailbox.counters.len();
        let resp = mutrefbytes::<CmStatusResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.used_usage_storage = len as u32;
        resp.total_usage_storage = KEY_USAGE_MAX as u32;
        Ok(core::mem::size_of::<CmStatusResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn import(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmImportReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmImportReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        let key_usage = CmKeyUsage::from(cmd.key_usage);

        match (key_usage, cmd.input_size) {
            (CmKeyUsage::Aes | CmKeyUsage::Mldsa, 32) => (),
            (CmKeyUsage::Ecdsa, 48) => (),
            (CmKeyUsage::Hmac, 48 | 64) => (),
            _ => Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?,
        }

        let raw_key = &cmd.input[..cmd.input_size as usize];
        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: cmd.input_size as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::Aes) {
                drivers.cryptographic_mailbox.add_counter()?
            } else {
                [0u8; 3]
            },
            usage_counter: 0,
            key_material: [0u8; CMK_MAX_KEY_SIZE_BITS / 8],
        };
        unencrypted_cmk.key_material[..raw_key.len()].copy_from_slice(raw_key);

        let encrypted_cmk = drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?;

        let resp = mutrefbytes::<CmImportResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.cmk = transmute!(encrypted_cmk);
        Ok(core::mem::size_of::<CmImportResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn delete(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() != core::mem::size_of::<CmDeleteReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let encrypted_cmk =
            EncryptedCmk::ref_from_bytes(&cmd_bytes[core::mem::offset_of!(CmDeleteReq, cmk)..])
                .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let decrypted_cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if matches!(
            CmKeyUsage::from(decrypted_cmk.key_usage as u32),
            CmKeyUsage::Aes
        ) {
            drivers
                .cryptographic_mailbox
                .delete_counter(decrypted_cmk.key_id())?;
        }

        let resp = mutrefbytes::<MailboxRespHeader>(resp)?;
        *resp = MailboxRespHeader::default();
        Ok(core::mem::size_of::<MailboxRespHeader>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn clear(drivers: &mut Drivers, resp: &mut [u8]) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }

        drivers.cryptographic_mailbox.clear_counters();

        let resp = mutrefbytes::<MailboxRespHeader>(resp)?;
        *resp = MailboxRespHeader::default();
        Ok(core::mem::size_of::<MailboxRespHeader>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmShaInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmShaInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        let cm_hash_algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);

        if cmd.input_size as usize > cmd.input.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mut context = ShaContext {
            hash_algorithm: cm_hash_algorithm.into(),
            ..Default::default()
        };

        let data = &cmd.input[..cmd.input_size as usize];

        let data_len = match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let mut op = drivers.sha2_512_384.sha384_digest_init()?;
                op.update(data)?;
                op.save_buffer(&mut context.input_buffer)?
            }

            CmHashAlgorithm::Sha512 => {
                let mut op = drivers.sha2_512_384.sha512_digest_init()?;
                op.update(data)?;
                op.save_buffer(&mut context.input_buffer)?
            }
            _ => {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
            }
        };

        context.length = data_len as u32;

        // copy the intermediate hash if we had enough data to generate one
        if data_len >= SHA512_BLOCK_BYTE_SIZE {
            let mut intermediate_digest = drivers.sha2_512_384.sha512_read_digest();
            intermediate_digest.0.iter_mut().for_each(|x| {
                *x = x.swap_bytes();
            });
            context
                .intermediate_hash
                .copy_from_slice(intermediate_digest.as_bytes());
        }

        // Safety: we've copied the state, so it is safe to zeroize
        unsafe {
            Sha2_512_384::zeroize();
        }

        let resp = mutrefbytes::<CmShaInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.context = transmute!(context);
        Ok(core::mem::size_of::<CmShaInitResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmShaUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmShaUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.input_size as usize > cmd.input.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mut context: ShaContext = ShaContext::read_from_bytes(&cmd.context)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cm_hash_algorithm = context.hash_algorithm.into();
        let data = &cmd.input[..cmd.input_size as usize];

        let context_buffer_len = context.length as usize % SHA512_BLOCK_BYTE_SIZE;
        let resume_len = context.length as usize - context_buffer_len;
        let data_len = match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let mut op = drivers.sha2_512_384.sha384_digest_init()?;
                op.resume(
                    resume_len,
                    &context.intermediate_hash.into(),
                    &context.input_buffer[..context_buffer_len],
                )?;
                op.update(data)?;
                op.save_buffer(&mut context.input_buffer)?
            }
            CmHashAlgorithm::Sha512 => {
                let mut op = drivers.sha2_512_384.sha512_digest_init()?;
                op.resume(
                    resume_len,
                    &context.intermediate_hash.into(),
                    &context.input_buffer[..context_buffer_len],
                )?;
                op.update(data)?;
                op.save_buffer(&mut context.input_buffer)?
            }
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        context.length = data_len as u32;

        // copy the intermediate hash if we had enough data to generate new one
        if context_buffer_len + data.len() >= SHA512_BLOCK_BYTE_SIZE {
            let mut intermediate_digest = drivers.sha2_512_384.sha512_read_digest();
            intermediate_digest.0.iter_mut().for_each(|x| {
                *x = x.swap_bytes();
            });
            context
                .intermediate_hash
                .copy_from_slice(intermediate_digest.as_bytes());
        }

        // Safety: we've copied the state, so it is safe to zeroize
        unsafe {
            Sha2_512_384::zeroize();
        }

        let resp = mutrefbytes::<CmShaInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.context = transmute!(context);
        Ok(core::mem::size_of::<CmShaInitResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmShaUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmShaUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.input_size as usize > cmd.input.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let context: ShaContext = ShaContext::read_from_bytes(&cmd.context)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cm_hash_algorithm = context.hash_algorithm.into();
        let data = &cmd.input[..cmd.input_size as usize];

        let mut digest = [0u8; SHA512_HASH_SIZE];
        let context_buffer_len = context.length as usize % SHA512_BLOCK_BYTE_SIZE;
        let resume_len = context.length as usize - context_buffer_len;
        let len = match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let mut op = drivers.sha2_512_384.sha384_digest_init()?;
                op.resume(
                    resume_len,
                    &context.intermediate_hash.into(),
                    &context.input_buffer[..context_buffer_len],
                )?;
                op.update(data)?;
                let mut digest32 = Array4x12::default();
                op.finalize(&mut digest32)?;
                digest[..SHA384_DIGEST_BYTE_SIZE]
                    .copy_from_slice(&<[u8; SHA384_DIGEST_BYTE_SIZE]>::from(digest32));
                SHA384_DIGEST_BYTE_SIZE
            }
            CmHashAlgorithm::Sha512 => {
                let mut op = drivers.sha2_512_384.sha512_digest_init()?;
                op.resume(
                    resume_len,
                    &context.intermediate_hash.into(),
                    &context.input_buffer[..context_buffer_len],
                )?;
                op.update(data)?;
                let mut digest32 = Array4x16::default();
                op.finalize(&mut digest32)?;
                digest.copy_from_slice(&<[u8; SHA512_DIGEST_BYTE_SIZE]>::from(digest32));
                SHA512_DIGEST_BYTE_SIZE
            }
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        // Safety: we've copied the digest, so it is safe to zeroize
        unsafe {
            Sha2_512_384::zeroize();
        }

        let resp = mutrefbytes::<CmShaFinalResp>(resp)?;
        resp.hdr = MailboxRespHeaderVarSize::default();
        resp.hdr.data_len = len as u32;
        resp.hash = digest;
        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn random_generate(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmRandomGenerateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let cmd = CmRandomGenerateReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let size = cmd.size as usize;
        if size > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let resp = mutrefbytes::<CmRandomGenerateResp>(resp)?;
        resp.hdr = MailboxRespHeaderVarSize::default();
        resp.hdr.data_len = size as u32;

        for i in (0..size).step_by(48) {
            let rand: [u8; 48] = drivers.trng.generate()?.into();
            let len = rand.len().min(resp.data.len() - i);
            // check to prevent panic even though this is impossible
            if i > resp.data.len() {
                break;
            }
            resp.data[i..i + len].copy_from_slice(&rand[..len]);
        }
        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn random_stir(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmRandomStirReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmRandomStirReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);
        let size = (cmd.input_size as usize).next_multiple_of(MAX_SEED_WORDS * 4);
        if size > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let additional_data = <[u32; MAX_CMB_DATA_SIZE / 4]>::ref_from_bytes(&cmd.input).unwrap();
        drivers.trng.stir(&additional_data[..size / 4])?;
        Ok(0)
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn aes_256_encrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesEncryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesEncryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mode = CmAesMode::from(cmd.mode);

        if matches!(mode, CmAesMode::Cbc) && cmd.plaintext_size as usize % AES_BLOCK_SIZE_BYTES != 0
        {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;
        let (key, _) = LEArray4x8::ref_from_prefix(&cmk.key_material).unwrap();
        let iv: [u8; 16] = drivers.trng.generate()?.as_bytes()[..16]
            .try_into()
            .unwrap();
        let iv: LEArray4x4 = transmute!(iv);

        let resp = mutrefbytes::<CmAesEncryptInitResp>(resp)?;

        let unencrypted_context = match mode {
            CmAesMode::Cbc => drivers.aes.aes_256_cbc(
                key,
                &iv,
                AesOperation::Encrypt,
                plaintext,
                &mut resp.ciphertext,
            )?,
            CmAesMode::Ctr => {
                drivers
                    .aes
                    .aes_256_ctr(key, &iv, 0, plaintext, &mut resp.ciphertext)?
            }
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.iv = iv.into();
        resp.hdr.context = transmute!(encrypted_context);
        resp.hdr.ciphertext_size = plaintext.len() as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_encrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesEncryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesEncryptUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let encrypted_context = EncryptedAesContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let context = &drivers.cryptographic_mailbox.decrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;

        let mode = CmAesMode::from(context.mode);
        if matches!(mode, CmAesMode::Cbc) && cmd.plaintext_size as usize % AES_BLOCK_SIZE_BYTES != 0
        {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let resp = mutrefbytes::<CmAesResp>(resp)?;
        match mode {
            CmAesMode::Cbc => {
                Self::aes_256_cbc_op(drivers, context, plaintext, AesOperation::Encrypt, resp)
            }
            CmAesMode::Ctr => Self::aes_256_ctr_op(drivers, context, plaintext, resp),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn aes_256_cbc_decrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesDecryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesDecryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mode = CmAesMode::from(cmd.mode);

        if matches!(mode, CmAesMode::Cbc)
            && cmd.ciphertext_size as usize % AES_BLOCK_SIZE_BYTES != 0
        {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;
        let (key, _) = LEArray4x8::ref_from_prefix(&cmk.key_material).unwrap();
        let resp = mutrefbytes::<CmAesResp>(resp)?;
        let iv = LEArray4x4::ref_from_bytes(&cmd.iv[..]).unwrap();
        let unencrypted_context = match mode {
            CmAesMode::Cbc => drivers.aes.aes_256_cbc(
                key,
                iv,
                AesOperation::Decrypt,
                ciphertext,
                &mut resp.output,
            )?,
            CmAesMode::Ctr => drivers
                .aes
                .aes_256_ctr(key, iv, 0, ciphertext, &mut resp.output)?,
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.context = transmute!(encrypted_context);
        resp.hdr.output_size = ciphertext.len() as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_cbc_decrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesDecryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesDecryptUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];
        let encrypted_context = EncryptedAesContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let context = &drivers.cryptographic_mailbox.decrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let mode: CmAesMode = context.mode.into();
        if matches!(mode, CmAesMode::Cbc)
            && cmd.ciphertext_size as usize % AES_BLOCK_SIZE_BYTES != 0
        {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let resp = mutrefbytes::<CmAesResp>(resp)?;
        match mode {
            CmAesMode::Cbc => {
                Self::aes_256_cbc_op(drivers, context, ciphertext, AesOperation::Decrypt, resp)
            }
            CmAesMode::Ctr => Self::aes_256_ctr_op(drivers, context, ciphertext, resp),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        }
    }

    #[inline(always)]
    fn aes_256_cbc_op(
        drivers: &mut Drivers,
        context: &AesContext,
        input: &[u8],
        op: AesOperation,
        resp: &mut CmAesResp,
    ) -> CaliptraResult<usize> {
        let new_unencrypted_context = drivers.aes.aes_256_cbc(
            &context.key,
            &context.last_ciphertext,
            op,
            input,
            &mut resp.output,
        )?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.context = transmute!(new_encrypted_context);
        resp.hdr.output_size = input.len() as u32;
        resp.partial_len()
    }

    #[inline(always)]
    fn aes_256_ctr_op(
        drivers: &mut Drivers,
        context: &AesContext,
        input: &[u8],
        resp: &mut CmAesResp,
    ) -> CaliptraResult<usize> {
        let new_unencrypted_context = drivers.aes.aes_256_ctr(
            &context.key,
            &context.last_ciphertext,
            context.last_block_index as usize,
            input,
            &mut resp.output,
        )?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.context = transmute!(new_encrypted_context);
        resp.hdr.output_size = input.len() as u32;
        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn aes_256_gcm_encrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmEncryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmEncryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.aad_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let aad = &cmd.aad[..cmd.aad_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if cmk.length as usize > cmk.key_material.len() {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        let iv_arr;
        let key_usage: CmKeyUsage = CmKeyUsage::from(cmk.key_usage as u32);

        let (key, iv) = if cmd.flags != 0 {
            if !matches!(key_usage, CmKeyUsage::Hmac) {
                Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
            }
            let spdm_version: SpdmVersion = (cmd.flags as u8).try_into()?;
            let (key, iv) = Self::spdm_derive_key_and_iv(
                drivers,
                &cmk.key_material[..cmk.length as usize],
                spdm_version,
            )?;
            iv_arr = iv;
            (key, AesGcmIv::Array(&iv_arr))
        } else {
            // increment and check usage
            if !matches!(key_usage, CmKeyUsage::Aes) {
                Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
            }
            let counter = drivers.cryptographic_mailbox.increment_counter(&cmk)?;
            if counter > GCM_MAX_KEY_USES {
                Err(CaliptraError::RUNTIME_GCM_KEY_USAGE_LIMIT_REACHED)?;
            }
            let key: [u8; 32] = cmk.key_material[..32].try_into().unwrap();
            (transmute!(key), AesGcmIv::Random)
        };

        let unencrypted_context = drivers
            .aes
            .aes_256_gcm_init(&mut drivers.trng, &key, iv, aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmEncryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.iv = unencrypted_context.iv.0;
        resp.context = transmute!(encrypted_context);
        Ok(core::mem::size_of::<CmAesGcmEncryptInitResp>())
    }

    fn xor_iv(iv: &LEArray4x3, counter: &[u8; 8], big_endian_counter_xor: bool) -> LEArray4x3 {
        if big_endian_counter_xor {
            let counter = u64::from_be_bytes(*counter);
            LEArray4x3::new([
                iv.0[0],
                iv.0[1] ^ (counter & 0xffff_ffff) as u32,
                iv.0[2] ^ (counter >> 32) as u32,
            ])
        } else {
            let counter = u64::from_le_bytes(*counter);
            LEArray4x3::new([
                iv.0[0] ^ (counter & 0xffff_ffff) as u32,
                iv.0[1] ^ (counter >> 32) as u32,
                iv.0[2],
            ])
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn aes_256_gcm_spdm_encrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmSpdmEncryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmSpdmEncryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.aad_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let aad = &cmd.aad[..cmd.aad_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if cmk.length as usize > cmk.key_material.len() {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        let key_usage = CmKeyUsage::from(cmk.key_usage as u32);

        if !matches!(key_usage, CmKeyUsage::Hmac) {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }
        let spdm_flags = SpdmFlags(cmd.spdm_flags);
        let spdm_version: SpdmVersion = (spdm_flags.version() as u8).try_into()?;
        let (key, iv) = Self::spdm_derive_key_and_iv(
            drivers,
            &cmk.key_material[..cmk.length as usize],
            spdm_version,
        )?;
        let iv = Self::xor_iv(&iv, &cmd.spdm_counter, spdm_flags.counter_big_endian() == 1);
        let iv = AesGcmIv::Array(&iv);

        let unencrypted_context = drivers
            .aes
            .aes_256_gcm_init(&mut drivers.trng, &key, iv, aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmSpdmEncryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.context = transmute!(encrypted_context);
        Ok(core::mem::size_of::<CmAesGcmSpdmEncryptInitResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_encrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmEncryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmEncryptUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_context = EncryptedAesGcmContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let resp = mutrefbytes::<CmAesGcmEncryptUpdateResp>(resp)?;
        let (written, new_unencrypted_context) =
            drivers
                .aes
                .aes_256_gcm_encrypt_update(context, plaintext, &mut resp.ciphertext)?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.context = transmute!(new_encrypted_context);
        resp.hdr.ciphertext_size = written as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_encrypt_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmEncryptFinalReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmEncryptFinalReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_context = EncryptedAesGcmContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let resp = mutrefbytes::<CmAesGcmEncryptFinalResp>(resp)?;
        let (written, tag) =
            drivers
                .aes
                .aes_256_gcm_encrypt_final(context, plaintext, &mut resp.ciphertext)?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.tag = tag.0;
        resp.hdr.ciphertext_size = written as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.aad_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let aad = &cmd.aad[..cmd.aad_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if cmk.length as usize > cmk.key_material.len() {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        let iv_arr;
        let key_usage: CmKeyUsage = CmKeyUsage::from(cmk.key_usage as u32);
        let cmd_iv: LEArray4x3 = cmd.iv.into();

        let (key, iv) = if cmd.flags != 0 {
            if !matches!(key_usage, CmKeyUsage::Hmac) {
                Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
            }
            let spdm_version: SpdmVersion = (cmd.flags as u8).try_into()?;
            let (key, iv) = Self::spdm_derive_key_and_iv(
                drivers,
                &cmk.key_material[..cmk.length as usize],
                spdm_version,
            )?;
            iv_arr = iv;
            (key, AesGcmIv::Array(&iv_arr))
        } else {
            // check usage
            if !matches!(key_usage, CmKeyUsage::Aes) {
                Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
            }
            let key: [u8; 32] = cmk.key_material[..32].try_into().unwrap();
            (transmute!(key), (&cmd_iv).into())
        };

        let unencrypted_context = drivers
            .aes
            .aes_256_gcm_init(&mut drivers.trng, &key, iv, aad)?;

        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmDecryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.iv = unencrypted_context.iv.0;
        resp.context = transmute!(encrypted_context);

        Ok(core::mem::size_of::<CmAesGcmDecryptInitResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_spdm_decrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmSpdmDecryptInitReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmSpdmDecryptInitReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.aad_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let aad = &cmd.aad[..cmd.aad_size as usize];

        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if cmk.length as usize > cmk.key_material.len() {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        let key_usage: CmKeyUsage = CmKeyUsage::from(cmk.key_usage as u32);

        if !matches!(key_usage, CmKeyUsage::Hmac) {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }
        let spdm_version: SpdmVersion = (cmd.spdm_flags as u8).try_into()?;
        let (key, iv) = Self::spdm_derive_key_and_iv(
            drivers,
            &cmk.key_material[..cmk.length as usize],
            spdm_version,
        )?;
        let iv = Self::xor_iv(&iv, &cmd.spdm_counter, (cmd.spdm_flags >> 8) & 1 == 1);
        let iv = AesGcmIv::Array(&iv);

        let unencrypted_context = drivers
            .aes
            .aes_256_gcm_init(&mut drivers.trng, &key, iv, aad)?;

        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmSpdmDecryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.context = transmute!(encrypted_context);

        Ok(core::mem::size_of::<CmAesGcmSpdmDecryptInitResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];

        let encrypted_context = EncryptedAesGcmContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let resp = mutrefbytes::<CmAesGcmDecryptUpdateResp>(resp)?;
        let (written, new_unencrypted_context) =
            drivers
                .aes
                .aes_256_gcm_decrypt_update(context, ciphertext, &mut resp.plaintext)?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.context = transmute!(new_encrypted_context);
        resp.hdr.plaintext_size = written as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptFinalReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptFinalReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        if cmd.tag_len as usize > 16 || (cmd.tag_len as usize) < 8 {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let tag_arr: [u8; 16] = transmute!(cmd.tag);
        let tag = &tag_arr[..cmd.tag_len as usize];
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];

        let encrypted_context = EncryptedAesGcmContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let resp = mutrefbytes::<CmAesGcmDecryptFinalResp>(resp)?;
        let (written, tag_verified) =
            drivers
                .aes
                .aes_256_gcm_decrypt_final(context, ciphertext, &mut resp.plaintext, tag)?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.tag_verified = tag_verified as u32;
        resp.hdr.plaintext_size = written as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdh_generate(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmEcdhGenerateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let seed = drivers.trng.generate()?;
        let nonce = drivers.trng.generate()?;
        let mut priv_key_out = Array4x12::default();
        let pub_key = drivers.ecc384.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &nonce,
            &mut drivers.trng,
            Ecc384PrivKeyOut::Array4x12(&mut priv_key_out),
        )?;

        let mut plaintext_context = [0u8; CMB_ECDH_CONTEXT_SIZE];
        let priv_key_out_bytes = priv_key_out.as_bytes();
        plaintext_context[..priv_key_out_bytes.len()].copy_from_slice(priv_key_out_bytes);

        let encrypted_context = drivers.cryptographic_mailbox.encrypt_ecdh_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &plaintext_context,
        )?;

        let resp = mutrefbytes::<CmEcdhGenerateResp>(resp)?;
        // build the exchange data
        // format x (48 bytes) followed by y (48 bytes)
        let pub_x: [u8; 48] = pub_key.x.into();
        let pub_y: [u8; 48] = pub_key.y.into();
        resp.exchange_data[0..48].copy_from_slice(&pub_x[..]);
        resp.exchange_data[48..96].copy_from_slice(&pub_y[..]);

        resp.hdr = MailboxRespHeader::default();
        resp.context = transmute!(encrypted_context);
        Ok(core::mem::size_of::<CmEcdhGenerateResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdh_finish(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmEcdhFinishReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let cmd = CmEcdhFinishReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let encrypted_context =
            EncryptedEcdhContext::ref_from_bytes(&cmd.context).map_err(|_|
             // should be impossible
            CaliptraError::RUNTIME_INTERNAL)?;

        let context = drivers.cryptographic_mailbox.decrypt_ecdh_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let priv_key: [u8; 48] = context[0..48].try_into().unwrap();
        // it's already in HW format
        let priv_key: Array4x12 = transmute!(priv_key);

        let x: [u8; 48] = cmd.incoming_exchange_data[0..48].try_into().unwrap();
        let x: Array4x12 = x.into();
        let y: [u8; 48] = cmd.incoming_exchange_data[48..96].try_into().unwrap();
        let y: Array4x12 = y.into();
        let pub_key = Ecc384PubKey { x, y };

        let key_usage: CmKeyUsage = cmd.key_usage.into();
        if key_usage == CmKeyUsage::Reserved {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mut shared_key_out = Array4x12::default();
        drivers.ecc384.ecdh(
            Ecc384PrivKeyIn::Array4x12(&priv_key),
            &pub_key,
            &mut drivers.trng,
            Ecc384PrivKeyOut::Array4x12(&mut shared_key_out),
        )?;

        // convert out of HW format
        shared_key_out.0.iter_mut().for_each(|x| {
            *x = x.swap_bytes();
        });

        let key_len = match key_usage {
            CmKeyUsage::Aes => 32,
            _ => 48,
        };
        let raw_key = &shared_key_out.as_bytes()[..key_len];
        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_len as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::Aes) {
                drivers.cryptographic_mailbox.add_counter()?
            } else {
                [0u8; 3]
            },
            usage_counter: 0,
            key_material: [0u8; CMK_MAX_KEY_SIZE_BITS / 8],
        };
        unencrypted_cmk.key_material[..key_len].copy_from_slice(raw_key);

        let encrypted_cmk = drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?;

        let resp = mutrefbytes::<CmEcdhFinishResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.output = transmute!(encrypted_cmk);
        Ok(core::mem::size_of::<CmEcdhFinishResp>())
    }

    fn decrypt_hmac_key(drivers: &mut Drivers, cmk: &MailboxCmk) -> CaliptraResult<UnencryptedCmk> {
        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        match (cmk.length, CmKeyUsage::from(cmk.key_usage as u32)) {
            (48 | 64, CmKeyUsage::Hmac) => Ok(cmk),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn hmac(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        hmac(
            &mut drivers.hmac,
            &mut drivers.aes,
            &mut drivers.trng,
            drivers.cryptographic_mailbox.kek,
            cmd_bytes,
            resp,
        )
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn hmac_kdf_counter(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmHmacKdfCounterReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmHmacKdfCounterReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        let cm_hash_algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);
        let key_usage: CmKeyUsage = cmd.key_usage.into();
        let key_size = cmd.key_size as usize;

        Self::validate_hkdf_params(cm_hash_algorithm, key_usage, key_size)?;

        if cmd.label_size as usize > cmd.label.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let label = &cmd.label[..cmd.label_size as usize];

        let cmk = Self::decrypt_hmac_key(drivers, &cmd.kin)?;

        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_size as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::Aes) {
                drivers.cryptographic_mailbox.add_counter()?
            } else {
                [0u8; 3]
            },
            usage_counter: 0,
            key_material: [0u8; CMK_MAX_KEY_SIZE_BITS / 8],
        };

        match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let arr: [u8; 48] = cmk.key_material[..48].try_into().unwrap();
                let key: Array4x12 = arr.into();
                let mut tag = Array4x12::default();
                hmac_kdf(
                    &mut drivers.hmac,
                    (&key).into(),
                    label,
                    None,
                    &mut drivers.trng,
                    (&mut tag).into(),
                    HmacMode::Hmac384,
                )?;
                // convert out of HW format
                tag.0.iter_mut().for_each(|x| {
                    *x = x.swap_bytes();
                });
                // truncate the key
                let len = tag.as_bytes().len().min(key_size);
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag.as_bytes()[..len])
            }
            CmHashAlgorithm::Sha512 => {
                let arr: [u8; 64] = cmk.key_material[..64].try_into().unwrap();
                let key: Array4x16 = arr.into();
                let mut tag = Array4x16::default();
                hmac_kdf(
                    &mut drivers.hmac,
                    (&key).into(),
                    label,
                    None,
                    &mut drivers.trng,
                    (&mut tag).into(),
                    HmacMode::Hmac512,
                )?;
                // convert out of HW format
                tag.0.iter_mut().for_each(|x| {
                    *x = x.swap_bytes();
                });
                // truncate the key
                let len = tag.as_bytes().len().min(key_size);
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag.as_bytes()[..len])
            }
            _ => return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        let resp = mutrefbytes::<CmHmacKdfCounterResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.kout = transmute!(drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?);
        Ok(core::mem::size_of::<CmHmacKdfCounterResp>())
    }

    fn validate_hkdf_params(
        cm_hash_algorithm: CmHashAlgorithm,
        key_usage: CmKeyUsage,
        key_size: usize,
    ) -> CaliptraResult<()> {
        match (cm_hash_algorithm, key_usage, key_size) {
            (_, CmKeyUsage::Aes, 32) => {}
            (_, CmKeyUsage::Ecdsa, 48) => {}
            (_, CmKeyUsage::Mldsa, 32) => {}
            (CmHashAlgorithm::Sha384, CmKeyUsage::Hmac, 48) => {}
            (CmHashAlgorithm::Sha512, CmKeyUsage::Hmac, 64) => {}
            _ => return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn hkdf_extract(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() != core::mem::size_of::<CmHkdfExtractReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let cmd = CmHkdfExtractReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let cm_hash_algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);
        let ikm = Self::decrypt_hmac_key(drivers, &cmd.ikm)?;
        let salt = Self::decrypt_hmac_key(drivers, &cmd.salt)?;

        match (cm_hash_algorithm, ikm.length) {
            (CmHashAlgorithm::Sha384, 48) => {}
            (CmHashAlgorithm::Sha512, 64) => {}
            _ => return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        }

        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: ikm.length,
            key_usage: CmKeyUsage::Hmac as u32 as u8,
            id: [0u8; 3],
            usage_counter: 0,
            key_material: [0u8; CMK_MAX_KEY_SIZE_BITS / 8],
        };

        match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let mut tag = Array4x12::default();
                hkdf_extract(
                    &mut drivers.hmac,
                    &ikm.key_material[..48],
                    &salt.key_material[..48],
                    &mut drivers.trng,
                    (&mut tag).into(),
                    HmacMode::Hmac384,
                )?;
                // convert out of HW format
                tag.0.iter_mut().for_each(|x| {
                    *x = x.swap_bytes();
                });
                let len = tag.as_bytes().len();
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag.as_bytes()[..len])
            }
            CmHashAlgorithm::Sha512 => {
                let mut tag = Array4x16::default();
                hkdf_extract(
                    &mut drivers.hmac,
                    &ikm.key_material[..64],
                    &salt.key_material[..64],
                    &mut drivers.trng,
                    (&mut tag).into(),
                    HmacMode::Hmac512,
                )?;
                // convert out of HW format
                tag.0.iter_mut().for_each(|x| {
                    *x = x.swap_bytes();
                });
                let len = tag.as_bytes().len();
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag.as_bytes()[..len])
            }
            _ => return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        let resp = mutrefbytes::<CmHkdfExtractResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.prk = transmute!(drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?);
        Ok(core::mem::size_of::<CmHkdfExtractResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn hkdf_expand(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        if cmd_bytes.len() > core::mem::size_of::<CmHkdfExpandReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmHkdfExpandReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        let cm_hash_algorithm = CmHashAlgorithm::from(cmd.hash_algorithm);
        let key_usage: CmKeyUsage = cmd.key_usage.into();
        let key_size = cmd.key_size as usize;

        Self::validate_hkdf_params(cm_hash_algorithm, key_usage, key_size)?;

        if cmd.info_size as usize > cmd.info.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let info = &cmd.info[..cmd.info_size as usize];

        let cmk = Self::decrypt_hmac_key(drivers, &cmd.prk)?;

        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_size as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::Aes) {
                drivers.cryptographic_mailbox.add_counter()?
            } else {
                [0u8; 3]
            },
            usage_counter: 0,
            key_material: [0u8; CMK_MAX_KEY_SIZE_BITS / 8],
        };

        match cm_hash_algorithm {
            CmHashAlgorithm::Sha384 => {
                let tag = Self::hkdf_expand384(drivers, &cmk.key_material[..48], info)?;
                let tag = tag.as_bytes();
                // truncate the key
                let len = tag.len().min(key_size);
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag[..len])
            }
            CmHashAlgorithm::Sha512 => {
                let tag = Self::hkdf_expand512(drivers, &cmk.key_material[..64], info)?;
                let tag = tag.as_bytes();
                // truncate the key
                let len = tag.len().min(key_size);
                unencrypted_cmk.key_material[..len].copy_from_slice(&tag[..len])
            }
            _ => return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        };

        let resp = mutrefbytes::<CmHkdfExpandResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.okm = transmute!(drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?);
        Ok(core::mem::size_of::<CmHkdfExpandResp>())
    }

    fn decrypt_mldsa_seed(drivers: &mut Drivers, cmk: &MailboxCmk) -> CaliptraResult<LEArray4x8> {
        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if !matches!(CmKeyUsage::from(cmk.key_usage as u32), CmKeyUsage::Mldsa) {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let seed = &cmk.key_material[..MLDSA_SEED_SIZE];
        let seed: &[u8; MLDSA_SEED_SIZE] = seed.try_into().unwrap();
        Ok(seed.into())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn mldsa_public_key(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmMldsaPublicKeyReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let cmd = CmMldsaPublicKeyReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let seed = Self::decrypt_mldsa_seed(drivers, &cmd.cmk)?;
        let seed = Mldsa87Seed::Array4x8(&seed);
        let public_key = drivers.mldsa87.key_pair(seed, &mut drivers.trng, None)?;

        let resp = mutrefbytes::<CmMldsaPublicKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.public_key.copy_from_slice(public_key.as_bytes());
        Ok(core::mem::size_of::<CmMldsaPublicKeyResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn mldsa_sign(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmMldsaSignReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmMldsaSignReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.message_size as usize > cmd.message.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let msg = &cmd.message[..cmd.message_size as usize];

        let seed = Self::decrypt_mldsa_seed(drivers, &cmd.cmk)?;
        let seed = Mldsa87Seed::Array4x8(&seed);
        let pub_key = &drivers.mldsa87.key_pair(seed, &mut drivers.trng, None)?;

        let sign_rnd = LEArray4x8::default();

        let signature =
            drivers
                .mldsa87
                .sign_var(seed, pub_key, msg, &sign_rnd, &mut drivers.trng)?;

        let resp = mutrefbytes::<CmMldsaSignResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.signature.copy_from_slice(signature.as_bytes());
        Ok(core::mem::size_of::<CmMldsaSignResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn mldsa_verify(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmMldsaVerifyReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmMldsaVerifyReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.message_size as usize > cmd.message.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let msg = &cmd.message[..cmd.message_size as usize];

        let seed = Self::decrypt_mldsa_seed(drivers, &cmd.cmk)?;
        let seed = Mldsa87Seed::Array4x8(&seed);
        let pub_key = &drivers.mldsa87.key_pair(seed, &mut drivers.trng, None)?;

        let signature: &LEArray4x1157 = &cmd.signature.into();

        match drivers.mldsa87.verify_var(pub_key, msg, signature)? {
            Mldsa87Result::Success => {
                let resp = mutrefbytes::<MailboxRespHeader>(resp)?;
                *resp = MailboxRespHeader::default();
                Ok(core::mem::size_of::<MailboxRespHeader>())
            }
            Mldsa87Result::SigVerifyFailed => {
                Err(CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH)?
            }
        }
    }

    fn decrypt_ecdsa_seed(drivers: &mut Drivers, cmk: &MailboxCmk) -> CaliptraResult<Array4x12> {
        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        if !matches!(CmKeyUsage::from(cmk.key_usage as u32), CmKeyUsage::Ecdsa) {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let seed = &cmk.key_material[..ECC384_SCALAR_BYTE_SIZE];
        let seed: &[u8; ECC384_SCALAR_BYTE_SIZE] = seed.try_into().unwrap();
        Ok(seed.into())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdsa_public_key(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmEcdsaPublicKeyReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let cmd = CmEcdsaPublicKeyReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let seed = Self::decrypt_ecdsa_seed(drivers, &cmd.cmk)?;
        let mut ignore = Array4x12::default();
        let pub_key = drivers.ecc384.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &Array4x12::default(),
            &mut drivers.trng,
            Ecc384PrivKeyOut::Array4x12(&mut ignore),
        )?;
        let resp = mutrefbytes::<CmEcdsaPublicKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        let x: [u8; ECC384_SCALAR_BYTE_SIZE] = pub_key.x.into();
        let y: [u8; ECC384_SCALAR_BYTE_SIZE] = pub_key.y.into();
        resp.public_key_x.copy_from_slice(&x);
        resp.public_key_y.copy_from_slice(&y);
        Ok(core::mem::size_of::<CmEcdsaPublicKeyResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdsa_sign(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmEcdsaSignReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmEcdsaSignReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.message_size as usize > cmd.message.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        // hash the message
        let msg = &cmd.message[..cmd.message_size as usize];
        let hash = drivers.sha2_512_384.sha384_digest(msg)?;

        let seed = Self::decrypt_ecdsa_seed(drivers, &cmd.cmk)?;
        let mut priv_key: Array4x12 = Array4x12::default();
        let pub_key = &drivers.ecc384.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &Array4x12::default(),
            &mut drivers.trng,
            Ecc384PrivKeyOut::Array4x12(&mut priv_key),
        )?;

        let signature = drivers.ecc384.sign(
            Ecc384PrivKeyIn::Array4x12(&priv_key),
            pub_key,
            &hash,
            &mut drivers.trng,
        )?;

        let resp = mutrefbytes::<CmEcdsaSignResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.signature_r = signature.r.into();
        resp.signature_s = signature.s.into();
        Ok(core::mem::size_of::<CmEcdsaSignResp>())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdsa_verify(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() > core::mem::size_of::<CmEcdsaVerifyReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmEcdsaVerifyReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.message_size as usize > cmd.message.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        // hash the message
        let msg = &cmd.message[..cmd.message_size as usize];
        let hash = drivers.sha2_512_384.sha384_digest(msg)?;

        let seed = Self::decrypt_ecdsa_seed(drivers, &cmd.cmk)?;
        let mut priv_key: Array4x12 = Array4x12::default();
        let pub_key = &drivers.ecc384.key_pair(
            Ecc384Seed::Array4x12(&seed),
            &Array4x12::default(),
            &mut drivers.trng,
            Ecc384PrivKeyOut::Array4x12(&mut priv_key),
        )?;

        let signature_r: Array4x12 = cmd.signature_r.into();
        let signature_s: Array4x12 = cmd.signature_s.into();

        match drivers.ecc384.verify(
            pub_key,
            &hash,
            &Ecc384Signature {
                r: signature_r,
                s: signature_s,
            },
        )? {
            Ecc384Result::Success => {
                let resp = mutrefbytes::<MailboxRespHeader>(resp)?;
                *resp = MailboxRespHeader::default();
                Ok(core::mem::size_of::<MailboxRespHeader>())
            }
            Ecc384Result::SigVerifyFailed => {
                Err(CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH)?
            }
        }
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn derive_stable_key(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if cmd_bytes.len() != core::mem::size_of::<CmDeriveStableKeyReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let request = CmDeriveStableKeyReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;

        let key_type: CmStableKeyType = request.key_type.into();

        let aes_key = match key_type {
            CmStableKeyType::IDevId => AesKey::KV(KeyReadArgs::new(KEY_ID_STABLE_IDEV)),
            CmStableKeyType::LDevId => AesKey::KV(KeyReadArgs::new(KEY_ID_STABLE_LDEV)),
            CmStableKeyType::Reserved => Err(CaliptraError::DOT_INVALID_KEY_TYPE)?,
        };
        let k0 = cmac_kdf(&mut drivers.aes, aes_key, &request.info, None, 4)?;

        // Prepend "DOT Final" to info and use as label for HMAC KDF
        const PREFIX: &[u8] = b"DOT Final";
        let mut data = [0u8; CM_STABLE_KEY_INFO_SIZE_BYTES + PREFIX.len()];
        data[..PREFIX.len()].copy_from_slice(PREFIX);
        data[PREFIX.len()..].copy_from_slice(&request.info);

        let mut tag: Array4x16 = Array4x16::default();
        hmac_kdf(
            &mut drivers.hmac,
            (&Array4x16::from(k0)).into(),
            &data[..],
            None,
            &mut drivers.trng,
            (&mut tag).into(),
            HmacMode::Hmac512,
        )?;
        let mut key_material = [0u8; 64];
        for (i, word) in tag.0.iter().enumerate() {
            key_material[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        // Convert the tag to CMK
        let unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_material.len() as u16,
            key_usage: CmKeyUsage::Hmac as u32 as u8,
            id: [0u8; 3],
            usage_counter: 0,
            key_material,
        };

        let encrypted_cmk = drivers.cryptographic_mailbox.encrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_cmk,
        )?;

        let resp = mutrefbytes::<CmDeriveStableKeyResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.cmk = transmute!(encrypted_cmk);
        Ok(core::mem::size_of::<CmDeriveStableKeyResp>())
    }

    fn spdm_derive_key_and_iv(
        drivers: &mut Drivers,
        major_secret: &[u8],
        version: SpdmVersion,
    ) -> CaliptraResult<(LEArray4x8, LEArray4x3)> {
        // EncryptionKey = HKDF-Expand(major-secret, bin_str5, key_length);
        // IV = HKDF-Expand(major-secret, bin_str6, iv_length);
        // bin_str5 = BinConcat(key_length, Version, "key", null);
        // bin_str6 = BinConcat(iv_length, Version, "iv", null);
        let mut bin_str5 = [0u8; 13];
        let mut bin_str6 = [0u8; 12];
        spdm_bin_concat(32, version, "key", &[], &mut bin_str5)?;
        spdm_bin_concat(12, version, "iv", &[], &mut bin_str6)?;

        let mut key = [0u32; 8];
        let mut iv = [0u32; 3];

        match major_secret.len() {
            48 => {
                let hkdf_key = Self::hkdf_expand384(drivers, major_secret, &bin_str5)?;
                let hkdf_iv = Self::hkdf_expand384(drivers, major_secret, &bin_str6)?;
                key.copy_from_slice(&hkdf_key[..8]);
                iv.copy_from_slice(&hkdf_iv[..3]);
            }
            64 => {
                let hkdf_key = Self::hkdf_expand512(drivers, major_secret, &bin_str5)?;
                let hkdf_iv = Self::hkdf_expand512(drivers, major_secret, &bin_str6)?;
                key.copy_from_slice(&hkdf_key[..8]);
                iv.copy_from_slice(&hkdf_iv[..3]);
            }
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?,
        }
        let key = transmute!(key);
        let iv = transmute!(iv);
        Ok((key, iv))
    }

    fn hkdf_expand384(
        drivers: &mut Drivers,
        major_secret: &[u8],
        info: &[u8],
    ) -> CaliptraResult<[u32; 12]> {
        let arr: [u8; 48] = major_secret[..48]
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        let key: Array4x12 = arr.into();
        let mut tag = Array4x12::default();
        hkdf_expand(
            &mut drivers.hmac,
            (&key).into(),
            info,
            &mut drivers.trng,
            (&mut tag).into(),
            HmacMode::Hmac384,
        )?;
        // convert out of HW format
        tag.0.iter_mut().for_each(|x| {
            *x = x.swap_bytes();
        });
        // truncate the key
        tag.0[..12]
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)
    }

    fn hkdf_expand512(
        drivers: &mut Drivers,
        major_secret: &[u8],
        info: &[u8],
    ) -> CaliptraResult<[u32; 16]> {
        let arr: [u8; 64] = major_secret[..64]
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        let key: Array4x16 = arr.into();
        let mut tag = Array4x16::default();
        hkdf_expand(
            &mut drivers.hmac,
            (&key).into(),
            info,
            &mut drivers.trng,
            (&mut tag).into(),
            HmacMode::Hmac512,
        )?;

        // convert out of HW format
        tag.0.iter_mut().for_each(|x| {
            *x = x.swap_bytes();
        });
        Ok(tag.0)
    }

    /// Performs in-place AES-GCM decryption of data at an AXI address using DMA.
    ///
    /// This command:
    /// 1. Validates that the boot mode was EncryptedFirmware
    /// 2. Decrypts the CMK
    /// 3. Verifies the SHA384 hash of the encrypted data at the AXI address (first DMA pass)
    /// 4. Performs in-place AES-GCM decryption via DMA (second pass)
    /// 5. Returns whether the GCM tag was verified successfully
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_dma(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }

        // Validate boot mode - this command is only allowed when boot mode is EncryptedFirmware
        let boot_mode = drivers.persistent_data.get().rom.boot_mode;
        if boot_mode != BootMode::EncryptedFirmware {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptDmaReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptDmaReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        // Validate AAD length
        if cmd.aad_length as usize > cmd.aad.len() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let aad = &cmd.aad[..cmd.aad_length as usize];

        // Decrypt the CMK
        let encrypted_cmk = EncryptedCmk::ref_from_bytes(&cmd.cmk.0[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        let cmk = drivers.cryptographic_mailbox.decrypt_cmk(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_cmk,
        )?;

        // Validate key usage - must be AES key
        let key_usage = CmKeyUsage::from(cmk.key_usage as u32);
        if !matches!(key_usage, CmKeyUsage::Aes) {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        // Get the AXI address
        let axi_addr = AxiAddr {
            lo: cmd.axi_addr_lo,
            hi: cmd.axi_addr_hi,
        };
        let length = cmd.length;

        // First pass: Verify SHA384 of encrypted data
        // Create DMA recovery handle for SHA384 calculation
        let dma_recovery = DmaRecovery::new(
            drivers.soc_ifc.recovery_interface_base_addr().into(),
            drivers.soc_ifc.caliptra_base_axi_addr().into(),
            drivers.soc_ifc.mci_base_addr().into(),
            &drivers.dma,
        );

        let computed_digest = dma_recovery.sha384_image(
            &mut drivers.sha2_512_384_acc,
            axi_addr,
            length,
            AesDmaMode::None,
        )?;

        let computed_digest_bytes: [u8; 48] = computed_digest.into();
        if !constant_time_eq(&computed_digest_bytes, &cmd.encrypted_data_sha384) {
            Err(CaliptraError::RUNTIME_CMB_DMA_SHA384_MISMATCH)?;
        }

        // Extract key and IV from CMK
        let key: [u8; 32] = cmk.key_material[..32]
            .try_into()
            .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        let key: LEArray4x8 = transmute!(key);
        let iv: LEArray4x3 = LEArray4x3::new(cmd.iv);

        // Initialize AES-GCM for decryption - use initialize_aes_gcm directly
        // instead of aes_256_gcm_init to avoid zeroizing the engine before DMA
        let _iv = drivers.aes.initialize_aes_gcm(
            &mut drivers.trng,
            AesGcmIv::Array(&iv),
            AesKey::Array(&key),
            aad,
            AesOperation::Decrypt,
        )?;

        // Set the text phase with the length of the final partial block (or 16 if full)
        let partial_len = length as usize % 16;
        let text_len = if partial_len == 0 { 16 } else { partial_len };
        drivers.aes.gcm_set_text(text_len as u32);

        // Second pass: Perform in-place AES-GCM decryption via DMA
        // The DMA hardware will read from axi_addr, decrypt through AES engine,
        // and write back to axi_addr
        let dma_recovery = DmaRecovery::new(
            drivers.soc_ifc.recovery_interface_base_addr().into(),
            drivers.soc_ifc.caliptra_base_axi_addr().into(),
            drivers.soc_ifc.mci_base_addr().into(),
            &drivers.dma,
        );

        dma_recovery.transfer_payload_to_axi(
            axi_addr,
            length,
            axi_addr, // in-place: write back to same address
            false,    // read_fixed_addr
            false,    // write_fixed_addr
            AesDmaMode::AesGcm,
        )?;

        // Compute and verify the GCM tag
        let computed_tag = drivers.aes.compute_tag(aad.len(), length as usize)?;
        let expected_tag: LEArray4x4 = LEArray4x4::new(cmd.tag);
        let tag_verified = computed_tag.as_bytes() == expected_tag.as_bytes();

        // Build response
        let resp = mutrefbytes::<CmAesGcmDecryptDmaResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.tag_verified = tag_verified as u32;

        Ok(core::mem::size_of::<CmAesGcmDecryptDmaResp>())
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum SpdmVersion {
    V10,
    V11,
    V12,
    V13,
    V14,
}

impl TryFrom<u8> for SpdmVersion {
    type Error = CaliptraError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x10 => Ok(SpdmVersion::V10),
            0x11 => Ok(SpdmVersion::V11),
            0x12 => Ok(SpdmVersion::V12),
            0x13 => Ok(SpdmVersion::V13),
            0x14 => Ok(SpdmVersion::V14),
            _ => Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS),
        }
    }
}

// 1. Length   Binary  Little           16 bits
// 2. Version  Text    Text             8 bytes
// 3. Label    Text    Text             Variable
// 4. Context  Binary  Hash byte order  Hash.Length
fn spdm_bin_concat(
    length: u16,
    version: SpdmVersion,
    text: &str,
    context: &[u8],
    output: &mut [u8],
) -> CaliptraResult<()> {
    if 10 + text.len() + context.len() > output.len() {
        Err(CaliptraError::RUNTIME_INTERNAL)?;
    }
    output[0..2].copy_from_slice(&length.to_le_bytes());
    output[2..10].copy_from_slice(spdm_version_str(version));
    let text_bytes = text.as_bytes();
    output[10..10 + text_bytes.len()].copy_from_slice(text_bytes);
    output[10 + text_bytes.len()..10 + text_bytes.len() + context.len()].copy_from_slice(context);
    Ok(())
}

const fn spdm_version_str(version: SpdmVersion) -> &'static [u8; 8] {
    match version {
        // SPDM 1.0 does not support key exchange so has no need of this, but we include it anyway for completeness sake
        SpdmVersion::V10 => b"spdm1.0 ",
        SpdmVersion::V11 => b"spdm1.1 ",
        SpdmVersion::V12 => b"spdm1.2 ",
        SpdmVersion::V13 => b"spdm1.3 ",
        SpdmVersion::V14 => b"spdm1.4 ", // technically not in the spec but we include it because it was likely an oversight
    }
}
