/*++

Licensed under the Apache-2.0 license.

File Name:

    cryptographic_mailbox.rs

Abstract:

    File contains exports for the Cryptographic Mailbox API commands.

--*/

use crate::{mutrefbytes, Drivers};
use arrayvec::ArrayVec;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    CmAesDecryptInitReq, CmAesDecryptUpdateReq, CmAesEncryptInitReq, CmAesEncryptInitResp,
    CmAesEncryptUpdateReq, CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp,
    CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq,
    CmAesGcmDecryptUpdateResp, CmAesGcmEncryptFinalReq, CmAesGcmEncryptFinalResp,
    CmAesGcmEncryptInitReq, CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq,
    CmAesGcmEncryptUpdateResp, CmAesResp, CmEcdhFinishReq, CmEcdhFinishResp, CmEcdhGenerateReq,
    CmEcdhGenerateResp, CmHashAlgorithm, CmImportReq, CmImportResp, CmKeyUsage,
    CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq, CmShaFinalResp, CmShaInitReq,
    CmShaInitResp, CmShaUpdateReq, CmStatusResp, MailboxRespHeader, MailboxRespHeaderVarSize,
    ResponseVarSize, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_CONTEXT_SIZE,
    CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_SHA_CONTEXT_SIZE, CMK_MAX_KEY_SIZE_BITS, CMK_SIZE_BYTES,
    MAX_CMB_DATA_SIZE,
};
use caliptra_drivers::{
    sha2_512_384::{Sha2DigestOpTrait, SHA512_BLOCK_BYTE_SIZE, SHA512_HASH_SIZE},
    Aes, AesContext, AesGcmContext, AesGcmIv, AesKey, AesOperation, Array4x12, Array4x16,
    CaliptraResult, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Seed, Sha2_512_384,
    Trng, AES_BLOCK_SIZE_BYTES, AES_CONTEXT_SIZE_BYTES, AES_GCM_CONTEXT_SIZE_BYTES, MAX_SEED_WORDS,
};
use caliptra_error::CaliptraError;
use caliptra_image_types::{SHA384_DIGEST_BYTE_SIZE, SHA512_DIGEST_BYTE_SIZE};
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

pub const KEY_USAGE_MAX: usize = 256;

// We have 24 bits for the key ID.
const MAX_KEY_ID: u32 = 0xffffff;

/// Holds data for the cryptographic mailbox system.
#[derive(Default)]
pub struct CmStorage {
    initialized: bool,
    // Usage counters for individual GCM keys.
    counters: ArrayVec<KeyUsageInfo, KEY_USAGE_MAX>,
    // 1-up counter for KEK GCM IV
    kek_next_iv: u128,
    // KEK split into two key shares
    kek: ([u8; 32], [u8; 32]),
    // 1-up counter for context GCM IV
    context_next_iv: u128,
    // key for encrypting contexts
    context_key: ([u8; 32], [u8; 32]),
}

impl CmStorage {
    pub fn new() -> Self {
        Self {
            kek: ([0u8; 32], [0u8; 32]),
            context_key: ([0u8; 32], [0u8; 32]),
            ..Default::default()
        }
    }

    /// Initialize the cryptographic mailbox storage key and IV.
    /// This is done after the TRNG is initialized and CFI is configured.
    pub fn init(&mut self, trng: &mut Trng) -> CaliptraResult<()> {
        let kek_key_share0: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        let kek_key_share1: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        let kek_random_iv = trng.generate4()?;
        // we mask off the top bit so that we always have at least 2^95 usages left.
        self.context_next_iv = (((kek_random_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((kek_random_iv.1 as u128) << 32)
            | (kek_random_iv.2 as u128);
        self.kek = (transmute!(kek_key_share0), transmute!(kek_key_share1));

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

    fn encrypt_cmk(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_cmk: &UnencryptedCmk,
    ) -> CaliptraResult<EncryptedCmk> {
        let kek_iv: [u8; 12] = self.kek_next_iv.to_le_bytes()[..12].try_into().unwrap();
        self.kek_next_iv += 1;

        let plaintext = unencrypted_cmk.as_bytes();
        let mut ciphertext = [0u8; UNENCRYPTED_CMK_SIZE_BYTES];
        // Encrypt the CMK using the KEK
        let (iv, gcm_tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesGcmIv::Array(&kek_iv),
            AesKey::Split(&self.kek.0, &self.kek.1),
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

    fn decrypt_cmk(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_cmk: &EncryptedCmk,
    ) -> CaliptraResult<UnencryptedCmk> {
        let ciphertext = &encrypted_cmk.ciphertext;
        let mut plaintext = [0u8; UNENCRYPTED_CMK_SIZE_BYTES];
        aes.aes_256_gcm_decrypt(
            trng,
            &encrypted_cmk.iv,
            AesKey::Split(&self.kek.0, &self.kek.1),
            &[],
            ciphertext,
            &mut plaintext,
            &encrypted_cmk.gcm_tag,
        )?;
        UnencryptedCmk::read_from_bytes(&plaintext)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)
    }

    fn encrypt_aes_cbc_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_context: &AesContext,
    ) -> CaliptraResult<EncryptedAesCbcContext> {
        let context_iv: [u8; 12] = self.context_next_iv.to_le_bytes()[..12].try_into().unwrap();
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
        Ok(EncryptedAesCbcContext {
            iv,
            tag,
            ciphertext,
        })
    }

    fn decrypt_aes_cbc_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        encrypted_context: &EncryptedAesCbcContext,
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
        let context_iv: [u8; 12] = self.context_next_iv.to_le_bytes()[..12].try_into().unwrap();
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
        let context_iv: [u8; 12] = self.context_next_iv.to_le_bytes()[..12].try_into().unwrap();
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

const UNENCRYPTED_CMK_SIZE_BYTES: usize = 80;

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct UnencryptedCmk {
    version: u16,
    length: u16,
    key_usage: u8,
    id: [u8; 3],
    usage_counter: u64,
    key_material: [u8; CMK_MAX_KEY_SIZE_BITS / 8],
}

impl UnencryptedCmk {
    #[allow(unused)]
    fn key_id(&self) -> u32 {
        self.id[0] as u32 | ((self.id[1] as u32) << 8) | ((self.id[2] as u32) << 16)
    }
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct EncryptedCmk {
    pub domain: u32,
    pub domain_metadata: [u8; 16],
    pub iv: [u8; 12],
    pub ciphertext: [u8; UNENCRYPTED_CMK_SIZE_BYTES],
    pub gcm_tag: [u8; 16],
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
pub struct EncryptedAesCbcContext {
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: [u8; AES_CONTEXT_SIZE_BYTES],
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
pub struct EncryptedAesGcmContext {
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: [u8; AES_GCM_CONTEXT_SIZE_BYTES],
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
struct EncryptedEcdhContext {
    pub iv: [u8; 12],
    pub tag: [u8; 16],
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

        let valid = matches!((key_usage, cmd.input_size), (CmKeyUsage::AES, 32));
        if !valid {
            Err(CaliptraError::RUNTIME_CMB_INVALID_KEY_USAGE_AND_SIZE)?;
        }

        let raw_key = &cmd.input[..cmd.input_size as usize];
        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: cmd.input_size as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::AES) {
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
        if cmd_bytes.len() > core::mem::size_of::<CmRandomGenerateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmRandomGenerateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

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
    pub(crate) fn aes_256_cbc_encrypt_init(
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
        if cmd.plaintext_size as usize % AES_BLOCK_SIZE_BYTES != 0 {
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
        let key = &cmk.key_material[..32].try_into().unwrap();
        let iv = drivers.trng.generate()?.as_bytes()[..16]
            .try_into()
            .unwrap();

        let resp = mutrefbytes::<CmAesEncryptInitResp>(resp)?;

        let unencrypted_context = drivers.aes.aes_256_cbc(
            key,
            &iv,
            AesOperation::Encrypt,
            plaintext,
            &mut resp.ciphertext,
        )?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_cbc_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        resp.hdr.hdr = MailboxRespHeader::default();
        resp.hdr.iv = iv;
        resp.hdr.context = transmute!(encrypted_context);
        resp.hdr.ciphertext_size = plaintext.len() as u32;

        resp.partial_len()
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_cbc_encrypt_update(
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
        if cmd.plaintext_size as usize % AES_BLOCK_SIZE_BYTES != 0 {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_context = EncryptedAesCbcContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let resp = mutrefbytes::<CmAesResp>(resp)?;
        Self::aes_256_cbc_op(
            drivers,
            encrypted_context,
            plaintext,
            AesOperation::Encrypt,
            resp,
        )
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
        if cmd.ciphertext_size as usize % AES_BLOCK_SIZE_BYTES != 0 {
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
        let key = &cmk.key_material[..32].try_into().unwrap();
        let resp = mutrefbytes::<CmAesResp>(resp)?;
        let unencrypted_context = drivers.aes.aes_256_cbc(
            key,
            &cmd.iv,
            AesOperation::Decrypt,
            ciphertext,
            &mut resp.output,
        )?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_cbc_context(
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
        if cmd.ciphertext_size as usize % AES_BLOCK_SIZE_BYTES != 0 {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];
        let encrypted_context = EncryptedAesCbcContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let resp = mutrefbytes::<CmAesResp>(resp)?;
        Self::aes_256_cbc_op(
            drivers,
            encrypted_context,
            ciphertext,
            AesOperation::Decrypt,
            resp,
        )
    }

    #[inline(always)]
    fn aes_256_cbc_op(
        drivers: &mut Drivers,
        encrypted_context: &EncryptedAesCbcContext,
        input: &[u8],
        op: AesOperation,
        resp: &mut CmAesResp,
    ) -> CaliptraResult<usize> {
        let context = &drivers.cryptographic_mailbox.decrypt_aes_cbc_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let new_unencrypted_context = drivers.aes.aes_256_cbc(
            &context.key,
            &context.last_ciphertext,
            op,
            input,
            &mut resp.output,
        )?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_cbc_context(
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
        drivers.cryptographic_mailbox.increment_counter(&cmk)?;
        let key = &cmk.key_material[..32].try_into().unwrap();
        let unencrypted_context =
            drivers
                .aes
                .aes_256_gcm_init(&mut drivers.trng, key, AesGcmIv::Random, aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmEncryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.iv = unencrypted_context.iv;
        resp.context = transmute!(encrypted_context);
        Ok(core::mem::size_of::<CmAesGcmEncryptInitResp>())
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
        resp.hdr.tag = tag;
        resp.hdr.ciphertext_size = written as u32;

        resp.partial_len()
    }

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
        let key = &cmk.key_material[..32].try_into().unwrap();
        let unencrypted_context =
            drivers
                .aes
                .aes_256_gcm_init(&mut drivers.trng, key, AesGcmIv::Array(&cmd.iv), aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        let resp = mutrefbytes::<CmAesGcmDecryptInitResp>(resp)?;
        resp.hdr = MailboxRespHeader::default();
        resp.iv = unencrypted_context.iv;
        resp.context = transmute!(encrypted_context);

        Ok(core::mem::size_of::<CmAesGcmDecryptInitResp>())
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

        let tag = &cmd.tag[..cmd.tag_len as usize];
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];

        let encrypted_context = EncryptedAesGcmContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_gcm_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let resp = mutrefbytes::<CmAesGcmDecryptFinalResp>(resp)?;
        let (written, _computed_tag, tag_verified) =
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
        if cmd_bytes.len() > core::mem::size_of::<CmEcdhGenerateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmEcdhGenerateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

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
        if cmd_bytes.len() > core::mem::size_of::<CmEcdhFinishReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmEcdhFinishReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

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
            CmKeyUsage::AES => 32,
            _ => 48,
        };
        let raw_key = &shared_key_out.as_bytes()[..key_len];
        let mut unencrypted_cmk = UnencryptedCmk {
            version: 1,
            length: key_len as u16,
            key_usage: key_usage as u32 as u8,
            id: if matches!(key_usage, CmKeyUsage::AES) {
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
        resp.output_cmk = transmute!(encrypted_cmk);
        Ok(core::mem::size_of::<CmEcdhFinishResp>())
    }
}

// TODO: add buffer tests for AES encrypt and decrypt
