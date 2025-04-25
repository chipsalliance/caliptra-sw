/*++

Licensed under the Apache-2.0 license.

File Name:

    cryptographic_mailbox.rs

Abstract:

    File contains exports for the Cryptographic Mailbox API commands.

--*/

use crate::Drivers;
use arrayvec::ArrayVec;
use caliptra_cfi_derive_git::cfi_impl_fn;
use caliptra_common::mailbox_api::{
    CmAesGcmDecryptFinalReq, CmAesGcmDecryptFinalResp, CmAesGcmDecryptFinalRespHeader,
    CmAesGcmDecryptInitReq, CmAesGcmDecryptInitResp, CmAesGcmDecryptUpdateReq,
    CmAesGcmDecryptUpdateResp, CmAesGcmDecryptUpdateRespHeader, CmAesGcmEncryptFinalReq,
    CmAesGcmEncryptFinalResp, CmAesGcmEncryptFinalRespHeader, CmAesGcmEncryptInitReq,
    CmAesGcmEncryptInitResp, CmAesGcmEncryptUpdateReq, CmAesGcmEncryptUpdateResp,
    CmAesGcmEncryptUpdateRespHeader, CmEcdhFinishReq, CmEcdhFinishResp, CmEcdhGenerateReq,
    CmEcdhGenerateResp, CmHashAlgorithm, CmImportReq, CmImportResp, CmKeyUsage,
    CmRandomGenerateReq, CmRandomGenerateResp, CmRandomStirReq, CmShaFinalResp, CmShaInitReq,
    CmShaInitResp, CmShaUpdateReq, CmStatusResp, MailboxResp, MailboxRespHeader,
    MailboxRespHeaderVarSize, CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_CONTEXT_SIZE,
    CMB_ECDH_ENCRYPTED_CONTEXT_SIZE, CMB_ECDH_EXCHANGE_DATA_MAX_SIZE, CMB_SHA_CONTEXT_SIZE,
    CMK_MAX_KEY_SIZE_BITS, CMK_SIZE_BYTES, MAX_CMB_AES_MAX_OUTPUT_SIZE, MAX_CMB_DATA_SIZE,
};
use caliptra_drivers::{
    sha2_512_384::{Sha2DigestOpTrait, SHA512_BLOCK_BYTE_SIZE, SHA512_HASH_SIZE},
    Aes, AesContext, AesIv, AesKey, Array4x12, Array4x16, CaliptraResult, Ecc384PrivKeyIn,
    Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Seed, Sha2_512_384, Trng, AES_CONTEXT_SIZE_BYTES,
    MAX_SEED_WORDS,
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
            AesIv::Array(&kek_iv),
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

    fn encrypt_aes_context(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        unencrypted_context: &AesContext,
    ) -> CaliptraResult<EncryptedAesContext> {
        let context_iv: [u8; 12] = self.context_next_iv.to_le_bytes()[..12].try_into().unwrap();
        self.context_next_iv += 1;

        let mut ciphertext = [0u8; AES_CONTEXT_SIZE_BYTES];
        // Encrypt the context using the context key
        let (iv, tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesIv::Array(&context_iv),
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
            AesIv::Array(&context_iv),
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
pub struct EncryptedAesContext {
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: [u8; AES_CONTEXT_SIZE_BYTES],
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
    assert!(core::mem::size_of::<EncryptedAesContext>() == CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE);

const _: () =
    assert!(core::mem::size_of::<EncryptedEcdhContext>() == CMB_ECDH_ENCRYPTED_CONTEXT_SIZE);

pub(crate) struct Commands {}

impl Commands {
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn status(drivers: &mut Drivers) -> CaliptraResult<MailboxResp> {
        if !drivers.cryptographic_mailbox.initialized {
            Err(CaliptraError::RUNTIME_CMB_NOT_INITIALIZED)?;
        }
        let len = drivers.cryptographic_mailbox.counters.len();
        Ok(MailboxResp::CmStatus(CmStatusResp {
            hdr: MailboxRespHeader::default(),
            used_usage_storage: len as u32,
            total_usage_storage: KEY_USAGE_MAX as u32,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn import(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
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

        let cmk = transmute!(encrypted_cmk);
        Ok(MailboxResp::CmImport(CmImportResp {
            hdr: MailboxRespHeader::default(),
            cmk,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_init(drivers: &mut Drivers, cmd_bytes: &[u8]) -> CaliptraResult<MailboxResp> {
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

        let context = transmute!(context);
        Ok(MailboxResp::CmShaInit(CmShaInitResp {
            hdr: MailboxRespHeader::default(),
            context,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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

        let context = transmute!(context);
        Ok(MailboxResp::CmShaInit(CmShaInitResp {
            hdr: MailboxRespHeader::default(),
            context,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn sha_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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

        Ok(MailboxResp::CmShaFinal(CmShaFinalResp {
            hdr: MailboxRespHeaderVarSize {
                hdr: MailboxRespHeader::default(),
                data_len: len as u32,
            },
            hash: digest,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn random_generate(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if cmd_bytes.len() > core::mem::size_of::<CmRandomGenerateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmRandomGenerateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        let size = cmd.size as usize;
        if size > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let mut data = [0u8; MAX_CMB_DATA_SIZE];

        for i in (0..data.len()).step_by(48) {
            let rand: [u8; 48] = drivers.trng.generate()?.into();
            let len = 48.min(data.len() - i);
            data[i..i + len].copy_from_slice(&rand[..len]);
        }

        Ok(MailboxResp::CmRandomGenerate(CmRandomGenerateResp {
            hdr: MailboxRespHeaderVarSize {
                hdr: MailboxRespHeader::default(),
                data_len: size as u32,
            },
            data,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn random_stir(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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
        Ok(MailboxResp::Header(MailboxRespHeader::default()))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub(crate) fn aes_256_gcm_encrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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
        let key = &cmk.key_material[..32].try_into().unwrap();
        let unencrypted_context =
            drivers
                .aes
                .aes_256_gcm_init(&mut drivers.trng, key, AesIv::Random, aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        Ok(MailboxResp::CmAesGcmEncryptInit(CmAesGcmEncryptInitResp {
            hdr: MailboxRespHeader::default(),
            iv: unencrypted_context.iv,
            context: transmute!(encrypted_context),
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_encrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmEncryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmEncryptUpdateReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_context = EncryptedAesContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let mut ciphertext = [0u8; MAX_CMB_AES_MAX_OUTPUT_SIZE];
        let (written, new_unencrypted_context) =
            drivers
                .aes
                .aes_256_gcm_encrypt_update(context, plaintext, &mut ciphertext[..])?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        Ok(MailboxResp::CmAesGcmEncryptUpdate(
            CmAesGcmEncryptUpdateResp {
                hdr: CmAesGcmEncryptUpdateRespHeader {
                    hdr: MailboxRespHeader::default(),
                    context: transmute!(new_encrypted_context),
                    ciphertext_size: written as u32,
                },
                ciphertext,
            },
        ))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_encrypt_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmEncryptFinalReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmEncryptFinalReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.plaintext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let plaintext = &cmd.plaintext[..cmd.plaintext_size as usize];

        let encrypted_context = EncryptedAesContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let mut ciphertext = [0u8; MAX_CMB_AES_MAX_OUTPUT_SIZE];
        let (written, tag) =
            drivers
                .aes
                .aes_256_gcm_encrypt_final(context, plaintext, &mut ciphertext[..])?;

        Ok(MailboxResp::CmAesGcmEncryptFinal(
            CmAesGcmEncryptFinalResp {
                hdr: CmAesGcmEncryptFinalRespHeader {
                    hdr: MailboxRespHeader::default(),
                    tag,
                    ciphertext_size: written as u32,
                },
                ciphertext,
            },
        ))
    }

    pub(crate) fn aes_256_gcm_decrypt_init(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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
                .aes_256_gcm_init(&mut drivers.trng, key, AesIv::Array(&cmd.iv), aad)?;
        let encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &unencrypted_context,
        )?;

        Ok(MailboxResp::CmAesGcmDecryptInit(CmAesGcmDecryptInitResp {
            hdr: MailboxRespHeader::default(),
            iv: unencrypted_context.iv,
            context: transmute!(encrypted_context),
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_update(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptUpdateReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptUpdateReq::default();
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
        let mut plaintext = [0u8; MAX_CMB_AES_MAX_OUTPUT_SIZE];
        let (written, new_unencrypted_context) =
            drivers
                .aes
                .aes_256_gcm_decrypt_update(context, ciphertext, &mut plaintext[..])?;

        let new_encrypted_context = drivers.cryptographic_mailbox.encrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            &new_unencrypted_context,
        )?;

        Ok(MailboxResp::CmAesGcmDecryptUpdate(
            CmAesGcmDecryptUpdateResp {
                hdr: CmAesGcmDecryptUpdateRespHeader {
                    hdr: MailboxRespHeader::default(),
                    context: transmute!(new_encrypted_context),
                    plaintext_size: written as u32,
                },
                plaintext,
            },
        ))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn aes_256_gcm_decrypt_final(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
        if cmd_bytes.len() > core::mem::size_of::<CmAesGcmDecryptFinalReq>() {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        let mut cmd = CmAesGcmDecryptFinalReq::default();
        cmd.as_mut_bytes()[..cmd_bytes.len()].copy_from_slice(cmd_bytes);

        if cmd.ciphertext_size as usize > MAX_CMB_DATA_SIZE {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }
        if cmd.tag_len as usize > 16 {
            Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;
        }

        let tag = &cmd.tag[..cmd.tag_len as usize];
        let ciphertext = &cmd.ciphertext[..cmd.ciphertext_size as usize];

        let encrypted_context = EncryptedAesContext::ref_from_bytes(&cmd.context[..])
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS)?;

        let context = &drivers.cryptographic_mailbox.decrypt_aes_context(
            &mut drivers.aes,
            &mut drivers.trng,
            encrypted_context,
        )?;
        let mut plaintext = [0u8; MAX_CMB_AES_MAX_OUTPUT_SIZE];
        let (written, computed_tag, tag_verified) =
            drivers
                .aes
                .aes_256_gcm_decrypt_final(context, ciphertext, &mut plaintext[..], tag)?;

        Ok(MailboxResp::CmAesGcmDecryptFinal(
            CmAesGcmDecryptFinalResp {
                hdr: CmAesGcmDecryptFinalRespHeader {
                    hdr: MailboxRespHeader::default(),
                    tag_verified: tag_verified as u32,
                    tag: computed_tag,
                    plaintext_size: written as u32,
                },
                plaintext,
            },
        ))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdh_generate(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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

        let mut exchange_data = [0u8; CMB_ECDH_EXCHANGE_DATA_MAX_SIZE];
        // build the exchange data
        // format x (48 bytes) followed by y (48 bytes)
        let pub_x: [u8; 48] = pub_key.x.into();
        let pub_y: [u8; 48] = pub_key.y.into();
        exchange_data[0..48].copy_from_slice(&pub_x[..]);
        exchange_data[48..96].copy_from_slice(&pub_y[..]);

        Ok(MailboxResp::CmEcdhGenerate(CmEcdhGenerateResp {
            hdr: MailboxRespHeader::default(),
            context: transmute!(encrypted_context),
            exchange_data,
        }))
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    #[inline(never)]
    pub(crate) fn ecdh_finish(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
    ) -> CaliptraResult<MailboxResp> {
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

        let output_cmk = transmute!(encrypted_cmk);

        Ok(MailboxResp::CmEcdhFinish(CmEcdhFinishResp {
            hdr: MailboxRespHeader::default(),
            output_cmk,
        }))
    }
}

// TODO: add buffer tests for AES encrypt and decrypt
