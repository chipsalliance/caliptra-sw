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
    CmHashAlgorithm, CmImportReq, CmImportResp, CmKeyUsage, CmRandomGenerateReq,
    CmRandomGenerateResp, CmShaFinalResp, CmShaInitReq, CmShaInitResp, CmShaUpdateReq,
    CmStatusResp, MailboxResp, MailboxRespHeader, MailboxRespHeaderVarSize, CMB_SHA_CONTEXT_SIZE,
    CMK_MAX_KEY_SIZE_BITS, CMK_SIZE_BYTES, MAX_CMB_DATA_SIZE,
};
use caliptra_drivers::{
    sha2_512_384::{Sha2DigestOpTrait, SHA512_BLOCK_BYTE_SIZE, SHA512_HASH_SIZE},
    Aes, AesIv, AesKey, Array4x12, Array4x16, Array4x8, CaliptraResult, Sha2_512_384, Trng,
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
    kek: (Array4x8, Array4x8),
}

impl CmStorage {
    pub fn new() -> Self {
        Self {
            kek: (Array4x8::default(), Array4x8::default()),
            ..Default::default()
        }
    }

    /// Initialize the cryptographic mailbox storage key and IV.
    /// This is done after the TRNG is initialized and CFI is configured.
    pub fn init(&mut self, trng: &mut Trng) -> CaliptraResult<()> {
        let key_share0: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        let key_share1: [u32; 8] = trng.generate()?.0[..8].try_into().unwrap();
        let key_share0 = Array4x8::from(key_share0);
        let key_share1 = Array4x8::from(key_share1);
        let random_iv = trng.generate4()?;
        // we mask off the top bit so that we always have at least 2^95 usages left.
        self.kek_next_iv = (((random_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((random_iv.1 as u128) << 32)
            | (random_iv.2 as u128);
        self.kek = (key_share0, key_share1);
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
        let kek_iv = self.kek_next_iv;
        self.kek_next_iv += 1;

        let plaintext = unencrypted_cmk.as_bytes();
        let mut ciphertext = [0u8; UNENCRYPTED_CMK_SIZE_BYTES];
        // Encrypt the CMK using the KEK
        let (iv, gcm_tag) = aes.aes_256_gcm_encrypt(
            trng,
            AesIv::U96(kek_iv),
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

const _: () = assert!(core::mem::size_of::<UnencryptedCmk>() == UNENCRYPTED_CMK_SIZE_BYTES);
const _: () = assert!(core::mem::size_of::<EncryptedCmk>() == CMK_SIZE_BYTES);
const _: () = assert!(core::mem::size_of::<ShaContext>() == CMB_SHA_CONTEXT_SIZE);

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
}
