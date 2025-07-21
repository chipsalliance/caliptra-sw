/*++

Licensed under the Apache-2.0 license.

File Name:

    aes.rs

Abstract:

    Driver for AES hardware operations.

    Notes about how this hardware differs from other hardware:

    * Shadowed control registers need to be written twice.
    * Registers are in little-endian order rather than big-endian,
      so we cannot use our normal Array4xN types.

--*/

use crate::{
    kv_access::{KvAccess, KvAccessErr},
    CaliptraError, CaliptraResult, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, LEArray4x4,
    LEArray4x8, Trng,
};
use caliptra_api::mailbox::CmAesMode;
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::{aes::AesReg, aes_clp::AesClpReg};
use core::cmp::Ordering;
use zerocopy::{transmute, FromBytes, Immutable, IntoBytes, KnownLayout};

type AesKeyBlock = LEArray4x8;
type AesBlock = LEArray4x4;

pub const AES_BLOCK_SIZE_BYTES: usize = 16;
const _: () = assert!(AES_BLOCK_SIZE_BYTES == core::mem::size_of::<AesBlock>());
const _: () = assert!(32 == core::mem::size_of::<AesKeyBlock>());

const AES_IV_SIZE_BYTES: usize = 12;
pub const AES_BLOCK_SIZE_WORDS: usize = AES_BLOCK_SIZE_BYTES / 4;
const AES_MAX_DATA_SIZE: usize = 1024 * 1024;
pub const AES_GCM_CONTEXT_SIZE_BYTES: usize = 100;
pub const AES_CONTEXT_SIZE_BYTES: usize = 128;
/// From the CMAC specification
const R_B: u128 = 0x87;
const ZERO_BLOCK: AesBlock = AesBlock::new([0; AES_BLOCK_SIZE_WORDS]);

/// AES GCM IV
#[derive(Debug, Copy, Clone)]
pub enum AesGcmIv<'a> {
    Array(&'a [u8; 12]),
    Random,
}

impl<'a> From<&'a [u8; 12]> for AesGcmIv<'a> {
    fn from(value: &'a [u8; 12]) -> Self {
        Self::Array(value)
    }
}

/// AES Key
#[derive(Debug, Copy, Clone)]
pub enum AesKey<'a> {
    /// Array - 32 Bytes (256 bits)
    Array(&'a AesKeyBlock),

    /// Split key parts that are XOR'd together
    Split(&'a AesKeyBlock, &'a AesKeyBlock),

    /// Read from the key vault
    KV(KeyReadArgs),
}

impl AesKey<'_> {
    // returns true if the key must be sideloaded
    const fn sideload(&self) -> bool {
        matches!(self, AesKey::KV(_))
    }
}

impl<'a> From<&'a AesKeyBlock> for AesKey<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a AesKeyBlock) -> Self {
        Self::Array(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum AesMode {
    Ecb = 1 << 0,
    Cbc = 1 << 1,
    _Cfb = 1 << 2,
    _Ofb = 1 << 3,
    Ctr = 1 << 4,
    Gcm = 1 << 5,
    _None = (1 << 6) - 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesKeyLen {
    _128 = 1,
    _192 = 2,
    _256 = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesOperation {
    Encrypt = 1,
    Decrypt = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcmPhase {
    Init = 1 << 0,
    Restore = 1 << 1,
    Aad = 1 << 2,
    Text = 1 << 3,
    Save = 1 << 4,
    Tag = 1 << 5,
}

#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct AesGcmContext {
    pub key: AesKeyBlock,
    pub iv: [u8; 12],
    pub aad_len: u32,
    pub ghash_state: AesBlock,
    pub buffer_len: u32,
    pub buffer: [u8; 16],
    pub resreved: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<AesGcmContext>() == AES_GCM_CONTEXT_SIZE_BYTES);

#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, KnownLayout, PartialEq)]
pub struct AesContext {
    pub mode: u32,
    pub key: AesKeyBlock,
    pub last_ciphertext: AesBlock,
    pub last_block_index: u8,
    _padding: [u8; 75],
}

impl Default for AesContext {
    fn default() -> Self {
        Self {
            mode: 0,
            key: AesKeyBlock::default(),
            last_ciphertext: AesBlock::default(),
            last_block_index: 0,
            _padding: [0; 75],
        }
    }
}

const _: () = assert!(core::mem::size_of::<AesContext>() == AES_CONTEXT_SIZE_BYTES);

#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

/// AES cryptographic engine driver.
pub struct Aes {
    aes: AesReg,
    aes_clp: AesClpReg,
}

// the value of this mask is not important, but the AES engine must be programmed
// with the key split into two pieces that are XOR'd together.
const MASK: u32 = 0x1234_5678;

/// Wait for the AES engine to be idle.
/// Necessary before writing control registers.
fn wait_for_idle(aes: &caliptra_registers::aes::RegisterBlock<ureg::RealMmioMut<'_>>) {
    while !aes.status().read().idle() {}
}

#[allow(clippy::too_many_arguments)]
impl Aes {
    pub fn new(aes: AesReg, aes_clp: AesClpReg) -> Self {
        Self { aes, aes_clp }
    }

    // Ensures that only one copy of the AES registers are used
    // in any given context to ensure exclusive access.
    fn with_aes<T>(
        &mut self,
        f: impl FnOnce(
            caliptra_registers::aes::RegisterBlock<ureg::RealMmioMut<'_>>,
            caliptra_registers::aes_clp::RegisterBlock<ureg::RealMmioMut<'_>>,
        ) -> T,
    ) -> T {
        let aes = self.aes.regs_mut();
        let aes_clp = self.aes_clp.regs_mut();
        f(aes, aes_clp)
    }

    pub fn aes_256_gcm_init(
        &mut self,
        trng: &mut Trng,
        key: &AesKeyBlock,
        iv: AesGcmIv,
        aad: &[u8],
    ) -> CaliptraResult<AesGcmContext> {
        if aad.len() > AES_MAX_DATA_SIZE {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        let iv = self.initialize_aes_gcm(
            trng,
            iv,
            AesKey::Array(key),
            aad,
            AesOperation::Encrypt, // doesn't matter
        )?;

        let ghash_state = if aad.is_empty() {
            // Edge case where we have not actually done any AES operations,
            // so the GHASH state should not be saved.
            AesBlock::default()
        } else {
            self.save()
        };
        self.zeroize_internal();
        Ok(AesGcmContext {
            key: *key,
            iv,
            aad_len: aad.len() as u32,
            ghash_state,
            buffer_len: 0,
            buffer: [0; 16],
            resreved: [0; 16],
        })
    }

    /// Restores the AES context, updates with new plaintext,
    /// and returns the number of ciphertext bytes written and
    /// the new context.
    pub fn aes_256_gcm_encrypt_update(
        &mut self,
        context: &AesGcmContext,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraResult<(usize, AesGcmContext)> {
        self.aes_256_gcm_update(context, plaintext, ciphertext, AesOperation::Encrypt)
    }

    /// Restores the AES context, updates with new ciphertext,
    /// and returns the number of plaintext bytes written and
    /// the new context.
    pub fn aes_256_gcm_decrypt_update(
        &mut self,
        context: &AesGcmContext,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> CaliptraResult<(usize, AesGcmContext)> {
        self.aes_256_gcm_update(context, ciphertext, plaintext, AesOperation::Decrypt)
    }

    fn aes_256_gcm_update(
        &mut self,
        context: &AesGcmContext,
        mut input: &[u8],
        mut output: &mut [u8],
        op: AesOperation,
    ) -> CaliptraResult<(usize, AesGcmContext)> {
        let left = context.buffer_len as usize % AES_BLOCK_SIZE_BYTES;

        if output.len() < input.len() + left {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        let mut len = context.buffer_len as usize;

        if left + input.len() < AES_BLOCK_SIZE_BYTES {
            // not enough bytes to do a block, so save in the buffer and return
            let mut buffer = [0u8; AES_BLOCK_SIZE_BYTES];
            buffer[..left].copy_from_slice(&context.buffer[..left]);
            buffer[left..left + input.len()].copy_from_slice(input);
            len += input.len();
            self.zeroize_internal();
            return Ok((
                0,
                AesGcmContext {
                    key: context.key,
                    iv: context.iv,
                    aad_len: context.aad_len,
                    ghash_state: context.ghash_state,
                    buffer_len: len as u32,
                    buffer,
                    resreved: [0; 16],
                },
            ));
        }

        self.restore(
            AesKey::Array(&context.key),
            &context.iv,
            context.aad_len,
            context.buffer_len,
            context.ghash_state,
            op,
        )?;

        // check if we need to process the previous buffer
        let mut written = 0;
        if left > 0 {
            // guaranteed to have at least one block to do
            let mut buffer = [0u8; AES_BLOCK_SIZE_BYTES];
            buffer[..left].copy_from_slice(&context.buffer[..left]);
            let take = AES_BLOCK_SIZE_BYTES - left;
            buffer[left..].copy_from_slice(&input[..take]);
            input = &input[take..];
            len += take;
            self.read_write_data_gcm(&buffer, GcmPhase::Text, Some(output))?;
            output = &mut output[AES_BLOCK_SIZE_BYTES..];
            written += AES_BLOCK_SIZE_BYTES;
        }

        // Write blocks of input and read blocks of output.
        while input.len() >= AES_BLOCK_SIZE_BYTES {
            let take = AES_BLOCK_SIZE_BYTES;
            // should be impossible but needed to prevent panic
            if output.len() < take {
                Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
            }
            self.read_write_data_gcm(&input[..take], GcmPhase::Text, Some(output))?;
            written += take;
            output = &mut output[take..];
            input = &input[take..];
            len += take;
        }

        // Save the remaining plaintext in the buffer.
        len += input.len();
        let mut buffer = [0u8; AES_BLOCK_SIZE_BYTES];
        buffer[..input.len()].copy_from_slice(input);

        let ghash_state = if context.aad_len == 0 && context.buffer_len == 0 {
            // Edge case where we have not actually done any AES operations,
            // so the GHASH state should not be saved.
            AesBlock::default()
        } else {
            self.save()
        };
        self.zeroize_internal();
        Ok((
            written,
            AesGcmContext {
                key: context.key,
                iv: context.iv,
                aad_len: context.aad_len,
                ghash_state,
                buffer_len: len as u32,
                buffer,
                resreved: [0; 16],
            },
        ))
    }

    /// Computes the final ciphertext, and returns the number of ciphertext bytes
    /// written and the final 16-byte tag.
    pub fn aes_256_gcm_encrypt_final(
        &mut self,
        context: &AesGcmContext,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> CaliptraResult<(usize, [u8; AES_BLOCK_SIZE_BYTES])> {
        self.aes_256_gcm_final(context, plaintext, ciphertext, AesOperation::Encrypt)
    }

    /// Computes the final plaintext, and returns the number of plaintext bytes
    /// written and the final 16-byte tag, and whether the tags matched.
    pub fn aes_256_gcm_decrypt_final(
        &mut self,
        context: &AesGcmContext,
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8],
    ) -> CaliptraResult<(usize, [u8; AES_BLOCK_SIZE_BYTES], bool)> {
        if tag.len() > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG_SIZE)?;
        }
        let (written, computed_tag) =
            self.aes_256_gcm_final(context, ciphertext, plaintext, AesOperation::Decrypt)?;

        let tag_matches = constant_time_eq(tag, &computed_tag);
        Ok((written, computed_tag, tag_matches))
    }

    /// Restores the AES context, updates with new input,
    /// and returns the number of output bytes written and the final 16-byte tag.
    fn aes_256_gcm_final(
        &mut self,
        context: &AesGcmContext,
        mut input: &[u8],
        mut output: &mut [u8],
        op: AesOperation,
    ) -> CaliptraResult<(usize, [u8; AES_BLOCK_SIZE_BYTES])> {
        let left = context.buffer_len as usize % AES_BLOCK_SIZE_BYTES;

        if output.len() < input.len() + left {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        self.restore(
            AesKey::Array(&context.key),
            &context.iv,
            context.aad_len,
            context.buffer_len,
            context.ghash_state,
            op,
        )?;

        // check if we need to process the previous buffer
        let mut len = context.buffer_len as usize;
        let mut written = 0;
        let mut new_input = [0u8; AES_BLOCK_SIZE_BYTES];
        let mut input = if left > 0 {
            if left + input.len() >= AES_BLOCK_SIZE_BYTES {
                let mut buffer = [0u8; AES_BLOCK_SIZE_BYTES];
                buffer[..left].copy_from_slice(&context.buffer[..left]);
                let take = AES_BLOCK_SIZE_BYTES - left;
                buffer[left..].copy_from_slice(&input[..take]);
                input = &input[take..];
                len += take;
                self.read_write_data_gcm(&buffer, GcmPhase::Text, Some(output))?;
                output = &mut output[AES_BLOCK_SIZE_BYTES..];
                written += AES_BLOCK_SIZE_BYTES;
                input
            } else {
                // edge case where the buffer and input are not enough to do a block
                len -= left; // correct the length, which is added again later
                new_input[..left].copy_from_slice(&context.buffer[..left]);
                new_input[left..left + input.len()].copy_from_slice(input);
                &new_input[..left + input.len()]
            }
        } else {
            input
        };

        // Write blocks of plaintext and read blocks of ciphertext out.
        while input.len() >= AES_BLOCK_SIZE_BYTES {
            let take = AES_BLOCK_SIZE_BYTES;
            // should be impossible but needed to prevent panic
            if take > output.len() {
                Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
            }
            self.read_write_data_gcm(&input[..take], GcmPhase::Text, Some(output))?;
            output = &mut output[take..];
            input = &input[take..];
            len += take;
            written += take;
        }

        // Do the final block
        if !input.is_empty() {
            self.read_write_data_gcm(input, GcmPhase::Text, Some(output))?;
            len += input.len();
            written += input.len();
        }

        // Compute and return the tag
        let tag = self.compute_tag(context.aad_len as usize, len)?;
        Ok((written, tag))
    }

    /// Saves and returns the current GHASH state.
    fn save(&mut self) -> AesBlock {
        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Save as u32));
            }
            wait_for_idle(&aes);
            // Read out the GHASH state from the data out registers.
            let ghash_state = AesBlock::read_from_reg(aes.data_out());
            wait_for_idle(&aes);
            ghash_state
        })
    }

    /// Restores the GHASH state.
    fn restore(
        &mut self,
        key: AesKey,
        iv: &[u8; AES_IV_SIZE_BYTES],
        aad_len: u32,
        len: u32,
        ghash_state: AesBlock,
        op: AesOperation,
    ) -> CaliptraResult<()> {
        // No zerocopy since we can't guarantee that the
        // byte array is aligned to 4-byte boundaries.
        let iv = [
            u32::from_le_bytes(iv[0..4].try_into().unwrap()),
            u32::from_le_bytes(iv[4..8].try_into().unwrap()),
            u32::from_le_bytes(iv[8..12].try_into().unwrap()),
            // hardware quirk: the hardware seems to expect IV[3] to be
            // presented as a big-endian int instead of little-endian, like elsewhere.
            // The specs expect us to store the whole IV when saving and restoring,
            // but this is not necessary if we already know the length and can compute this,
            // and account for the different endianness of this register.
            (len / (AES_BLOCK_SIZE_BYTES as u32) + 2).swap_bytes(),
        ];

        // sideload the KV key before we program the control register
        if key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Gcm as u32)
                        .operation(op as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }

            wait_for_idle(&aes);

            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Init as u32).num_valid_bytes(16));
            }

            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);

            // Program the initial IV (last 4 bytes will be zero)
            for (i, ivi) in iv.into_iter().enumerate().take(3) {
                aes.iv().at(i).write(|_| ivi);
            }
            aes.iv().at(3).write(|_| 0);

            wait_for_idle(&aes);

            // if we haven't actually written any AAD or input, then
            // we can skip the restore operation.
            // This avoids some edge cases in the hardware.
            if aad_len == 0 && len == 0 {
                return Ok(());
            }

            // Restore the GHASH state to data_in registers, which will load the state into the
            // GHASH unit.
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Restore as u32));
            }
            wait_for_idle(&aes);
            ghash_state.write_to_reg(aes.data_in());
            wait_for_idle(&aes);
            // Program the IV (last 4 bytes may not be zero, unlike when doing normal init)
            for (i, ivi) in iv.into_iter().enumerate() {
                aes.iv().at(i).write(|_| ivi);
            }
            wait_for_idle(&aes);
            Ok::<(), CaliptraError>(())
        })
    }

    /// Calculate the AES-256-GCM encrypted ciphertext for the given plaintext.
    /// Returns the IV and the tag.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn aes_256_gcm_encrypt(
        &mut self,
        trng: &mut Trng,
        iv: AesGcmIv,
        key: AesKey,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag_size: usize,
    ) -> CaliptraResult<([u8; AES_IV_SIZE_BYTES], [u8; AES_BLOCK_SIZE_BYTES])> {
        if tag_size > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG_SIZE)?;
        }
        if ciphertext.len() < plaintext.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        self.aes_256_gcm_op(
            trng,
            iv,
            key,
            aad,
            plaintext,
            ciphertext,
            AesOperation::Encrypt,
        )
    }

    /// Calculate the AES-256-GCM decrypted plaintext for the given ciphertext.
    /// Returns the IV and the tag.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn aes_256_gcm_decrypt(
        &mut self,
        trng: &mut Trng,
        iv: &[u8; AES_IV_SIZE_BYTES],
        key: AesKey,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8],
    ) -> CaliptraResult<()> {
        if plaintext.len() < ciphertext.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if tag.len() > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG_SIZE)?;
        }
        let (_, computed_tag) = self.aes_256_gcm_op(
            trng,
            iv.into(),
            key,
            aad,
            ciphertext,
            plaintext,
            AesOperation::Decrypt,
        )?;

        if !constant_time_eq(tag, &computed_tag) {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG)?;
        }
        Ok(())
    }

    /// Initializes the AES engine for GCM mode and returns the IV used.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn initialize_aes_gcm(
        &mut self,
        trng: &mut Trng,
        iv: AesGcmIv,
        key: AesKey,
        aad: &[u8],
        op: AesOperation,
    ) -> CaliptraResult<[u8; AES_IV_SIZE_BYTES]> {
        if matches!(op, AesOperation::Decrypt) && matches!(iv, AesGcmIv::Random) {
            // should be impossible
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_STATE)?;
        }

        // No zerocopy since we can't guarantee that the
        // byte array is aligned to 4-byte boundaries.
        let iv = match iv {
            AesGcmIv::Array(iv) => [
                u32::from_le_bytes(iv[0..4].try_into().unwrap()),
                u32::from_le_bytes(iv[4..8].try_into().unwrap()),
                u32::from_le_bytes(iv[8..12].try_into().unwrap()),
            ],
            AesGcmIv::Random => trng.generate()?.0[0..3].try_into().unwrap(),
        };

        // sideload the KV key before we program the control register
        if key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Gcm as u32)
                        .operation(op as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }

            wait_for_idle(&aes);

            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Init as u32).num_valid_bytes(16));
            }

            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            // Program the IV (last 4 bytes must be 0).
            for (i, ivi) in iv.into_iter().enumerate() {
                aes.iv().at(i).write(|_| ivi);
            }
            aes.iv().at(3).write(|_| 0);

            wait_for_idle(&aes);

            Ok::<(), CaliptraError>(())
        })?;

        // Load the AAD
        if !aad.is_empty() {
            self.read_write_data_gcm(aad, GcmPhase::Aad, None)?;
        }
        Ok(transmute!(iv))
    }

    fn load_key(&mut self, key: AesKey<'_>) -> CaliptraResult<()> {
        self.with_aes(|aes, aes_clp| {
            wait_for_idle(&aes);
            // Program the key
            // No zerocopy since we can't guarantee that the
            // byte arrays are aligned to 4-byte boundaries.
            match key {
                AesKey::Array(&arr) => {
                    for (i, word) in arr.0.iter().enumerate() {
                        aes.key_share0().at(i).write(|_| *word ^ MASK);
                        aes.key_share1().at(i).write(|_| MASK);
                    }
                }
                AesKey::Split(&key1, &key2) => {
                    key1.write_to_reg(aes.key_share0());
                    key2.write_to_reg(aes.key_share1());
                }
                AesKey::KV(key) => KvAccess::copy_from_kv(
                    key,
                    aes_clp.aes_kv_rd_key_status(),
                    aes_clp.aes_kv_rd_key_ctrl(),
                )
                .map_err(|_| CaliptraError::DRIVER_AES_READ_KEY_KV_READ)?,
            }
            wait_for_idle(&aes);
            Ok(())
        })
    }

    /// Initializes the AES engine for CBC or CTR mode
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn initialize_aes_cbc_ctr(
        &mut self,
        iv: &AesBlock,
        key: AesKey,
        op: AesOperation,
        mode: AesMode,
    ) -> CaliptraResult<()> {
        // sideload the KV key before we program the control register
        if key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(mode as u32)
                        .operation(op as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }
            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }

        // Program the IV
        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            iv.write_to_reg(aes.iv());
            wait_for_idle(&aes);
        });
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn aes_256_gcm_op(
        &mut self,
        trng: &mut Trng,
        iv: AesGcmIv,
        key: AesKey,
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        op: AesOperation,
    ) -> CaliptraResult<([u8; AES_IV_SIZE_BYTES], [u8; AES_BLOCK_SIZE_BYTES])> {
        if input.len() > AES_MAX_DATA_SIZE || output.len() > AES_MAX_DATA_SIZE {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if input.len() > output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        let iv = self.initialize_aes_gcm(trng, iv, key, aad, op)?;

        // Write blocks of plaintext and read blocks of ciphertext out.
        self.read_write_data_gcm(input, GcmPhase::Text, Some(output))?;

        let tag = self.compute_tag(aad.len(), input.len())?;
        Ok((iv, tag))
    }

    fn compute_tag(
        &mut self,
        aad_len: usize,
        text_len: usize,
    ) -> CaliptraResult<[u8; AES_BLOCK_SIZE_BYTES]> {
        // Compute the tag
        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed().write(|w| {
                    w.phase(GcmPhase::Tag as u32)
                        .num_valid_bytes(AES_BLOCK_SIZE_BYTES as u32)
                });
            }
        });
        // Compute the final block and load it into data_in
        let mut tag_input = [0u8; AES_BLOCK_SIZE_BYTES];
        // as per NIST SP 800-38D, algorithm 4, step 5, the last block
        // is len(A) || len(C), with the lengths in bits
        tag_input[0..8].copy_from_slice(&((aad_len * 8) as u64).to_be_bytes());
        tag_input[8..16].copy_from_slice(&((text_len * 8) as u64).to_be_bytes());
        self.load_data_block(&tag_input, 0)?;

        // Read out the tag.
        let mut tag_return = [0u8; AES_BLOCK_SIZE_BYTES];
        self.read_data_block(&mut tag_return, 0)?;

        self.zeroize_internal();
        Ok(tag_return)
    }

    fn read_data_block_u32(&mut self) -> AesBlock {
        let aes = self.aes.regs_mut();
        while !aes.status().read().output_valid() {}
        AesBlock::read_from_reg(aes.data_out())
    }

    fn read_data_block(&mut self, output: &mut [u8], block_num: usize) -> CaliptraResult<()> {
        // not possible but needed to prevent panic
        if block_num * AES_BLOCK_SIZE_BYTES >= output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        // read the data out
        let buffer = self.read_data_block_u32();
        let buffer: [u8; AES_BLOCK_SIZE_BYTES] = transmute!(buffer);

        let output = &mut output[block_num * AES_BLOCK_SIZE_BYTES..];
        let len = output.len().min(AES_BLOCK_SIZE_BYTES);
        let output = &mut output[..len];
        output.copy_from_slice(&buffer[..len]);
        Ok(())
    }

    fn load_data_block_u32(&mut self, data: AesBlock) {
        let aes = self.aes.regs_mut();
        while !aes.status().read().input_ready() {}
        data.write_to_reg(aes.data_in());
    }

    fn load_data_block(&mut self, data: &[u8], block_num: usize) -> CaliptraResult<()> {
        // not possible but needed to prevent panic
        if block_num * AES_BLOCK_SIZE_BYTES >= data.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        let data = &data[block_num * AES_BLOCK_SIZE_BYTES..];
        let data = &data[..AES_BLOCK_SIZE_BYTES.min(data.len())];
        let len = data.len();
        let mut padded_data = [0u8; AES_BLOCK_SIZE_BYTES];
        padded_data[..len].copy_from_slice(data);
        self.load_data_block_u32(transmute!(padded_data));
        Ok(())
    }

    fn read_write_data_gcm(
        &mut self,
        input: &[u8],
        phase: GcmPhase,
        output: Option<&mut [u8]>,
    ) -> CaliptraResult<()> {
        let num_blocks = input.len().div_ceil(AES_BLOCK_SIZE_BYTES);
        // length of the last block
        let partial_text_len = input.len() % AES_BLOCK_SIZE_BYTES;

        let read_output = output.is_some();
        let output = output.unwrap_or(&mut []);

        for i in 0..num_blocks {
            if i == 0 || ((i == num_blocks - 1) && (partial_text_len != 0)) {
                let num_bytes = if (i == num_blocks - 1) && partial_text_len != 0 {
                    partial_text_len
                } else {
                    AES_BLOCK_SIZE_BYTES
                };
                // set the mode and valid length
                self.with_aes(|aes, _| {
                    wait_for_idle(&aes);
                    for _ in 0..2 {
                        aes.ctrl_gcm_shadowed()
                            .write(|w| w.phase(phase as u32).num_valid_bytes(num_bytes as u32));
                    }
                });
            }

            self.load_data_block(input, i)?;
            if read_output {
                self.read_data_block(output, i)?;
            }
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn aes_256_ecb_decrypt_kv(&mut self, key: AesKey, input: &[u8; 64]) -> CaliptraResult<()> {
        if input.is_empty() {
            return Ok(());
        }
        if input.len() % AES_BLOCK_SIZE_BYTES != 0 {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        // Only KV 16 is a permitted input key to decrypt into KV 23.
        match key {
            AesKey::KV(KeyReadArgs { id }) if id != KeyId::KeyId16 => {
                Err(CaliptraError::RUNTIME_DRIVER_AES_READ_KEY_KV_READ)?;
            }
            _ => (),
        }

        if key.sideload() {
            self.load_key(key)?;
        }

        let mek_slot = KeyWriteArgs::new(
            KeyId::KeyId23, // MEK KV.
            KeyUsage::default().set_hmac_key_en().set_aes_key_en(),
        );

        self.with_aes::<CaliptraResult<()>>(|aes, aes_clp| {
            wait_for_idle(&aes);
            // We are only allowed to decrypt into KV 23.
            KvAccess::begin_copy_to_kv(
                aes_clp.aes_kv_wr_status(),
                aes_clp.aes_kv_wr_ctrl(),
                mek_slot,
            )
        })?;

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Ecb as u32)
                        .operation(AesOperation::Decrypt as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }
            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }
        for block_num in 0..input.chunks_exact(AES_BLOCK_SIZE_BYTES).len() {
            self.load_data_block(input, block_num)?;
        }

        // TODO(clundin): Double check error messages.
        self.with_aes::<CaliptraResult<()>>(|aes, aes_clp| {
            aes.trigger().write(|w| w.start(true));
            match KvAccess::end_copy_to_kv(aes_clp.aes_kv_wr_status(), mek_slot) {
                Ok(_) => Ok(()),
                Err(KvAccessErr::KeyRead) => {
                    Err(CaliptraError::RUNTIME_DRIVER_AES_READ_KEY_KV_READ)
                }
                Err(KvAccessErr::KeyWrite) => {
                    Err(CaliptraError::RUNTIME_DRIVER_AES_READ_KEY_KV_WRITE)
                }
                _ => Err(CaliptraError::RUNTIME_DRIVER_AES_READ_KEY_KV_UNKNOWN),
            }
        })?;

        self.zeroize_internal();
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn aes_256_ecb(
        &mut self,
        key: AesKey,
        op: AesOperation,
        input: &[u8],
        output: &mut [u8],
    ) -> CaliptraResult<()> {
        if input.is_empty() {
            return Ok(());
        }
        if input.len() % AES_BLOCK_SIZE_BYTES != 0 {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if output.len() < input.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        if key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Ecb as u32)
                        .operation(op as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }
            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }

        for block_num in 0..input.chunks_exact(AES_BLOCK_SIZE_BYTES).len() {
            self.load_data_block(input, block_num)?;
            self.read_data_block(output, block_num)?;
        }

        Ok(())
    }

    pub fn aes_256_cbc(
        &mut self,
        key: &AesKeyBlock,
        iv: &AesBlock,
        op: AesOperation,
        input: &[u8],
        output: &mut [u8],
    ) -> CaliptraResult<AesContext> {
        // trivial case is allowed
        if input.is_empty() {
            return Ok(AesContext {
                mode: CmAesMode::Cbc as u32,
                key: *key,
                last_ciphertext: *iv,
                ..Default::default()
            });
        }
        if input.len() % AES_BLOCK_SIZE_BYTES != 0 {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if output.len() < input.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        self.initialize_aes_cbc_ctr(iv, AesKey::Array(key), op, AesMode::Cbc)?;

        let num_blocks = input.len() / AES_BLOCK_SIZE_BYTES;
        // the compiler cannot reason that this is impossible so
        // check these lengthe to prevent panic
        if num_blocks == 0 || num_blocks * AES_BLOCK_SIZE_BYTES > output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        // the CBC engine operates in staggered mode, so handle
        // special cases of 1 or 2 blocks separately

        if num_blocks == 1 {
            self.load_data_block(input, 0)?;
            self.read_data_block(output, 0)?;
        } else if num_blocks == 2 {
            self.load_data_block(input, 0)?;
            self.load_data_block(input, 1)?;
            self.read_data_block(output, 0)?;
            self.read_data_block(output, 1)?;
        } else {
            // load the initial block
            self.load_data_block(input, 0)?;

            // then operate in staggered mode
            for i in 1..num_blocks {
                self.load_data_block(input, i)?;
                self.read_data_block(output, i - 1)?;
            }
            // now read the last output block
            self.read_data_block(output, num_blocks - 1)?;
        }

        let last_ciphertext: [u8; AES_BLOCK_SIZE_BYTES] = if op == AesOperation::Encrypt {
            output[(num_blocks - 1) * AES_BLOCK_SIZE_BYTES..num_blocks * AES_BLOCK_SIZE_BYTES]
                .try_into()
                .unwrap()
        } else {
            input[(num_blocks - 1) * AES_BLOCK_SIZE_BYTES..num_blocks * AES_BLOCK_SIZE_BYTES]
                .try_into()
                .unwrap()
        };

        self.zeroize_internal();
        Ok(AesContext {
            mode: CmAesMode::Cbc as u32,
            key: *key,
            last_ciphertext: transmute!(last_ciphertext),
            ..Default::default()
        })
    }

    fn add_iv(iv: &AesBlock, ctr: u32) -> AesBlock {
        // We write the IV as 4 32-bit words in little-endian order, but we have
        // to increment them as if they were big-endian.
        let iv: u128 = transmute!(*iv);
        let iv = iv.swap_bytes();
        let iv = iv + (ctr as u128);
        let iv = iv.swap_bytes();
        transmute!(iv)
    }

    pub fn aes_256_ctr(
        &mut self,
        key: &AesKeyBlock,
        iv: &AesBlock,
        block_index: usize, // index within a block
        mut input: &[u8],
        mut output: &mut [u8],
    ) -> CaliptraResult<AesContext> {
        // trivial case is allowed
        if input.is_empty() {
            return Ok(AesContext {
                mode: CmAesMode::Ctr as u32,
                key: *key,
                last_ciphertext: *iv,
                last_block_index: block_index as u8,
                ..Default::default()
            });
        }
        if output.len() < input.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if block_index >= AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        let mut iv = *iv;
        // encryption and decryption are the same in CTR mode
        self.initialize_aes_cbc_ctr(&iv, AesKey::Array(key), AesOperation::Encrypt, AesMode::Ctr)?;

        // handle partial first block
        if block_index > 0 {
            let mut partial_input = [0u8; AES_BLOCK_SIZE_BYTES];
            let mut partial_output = [0u8; AES_BLOCK_SIZE_BYTES];

            // check if there are not enough bytes to fill this partial block
            if input.len() + block_index < AES_BLOCK_SIZE_BYTES {
                partial_input[block_index..block_index + input.len()].copy_from_slice(input);
                self.load_data_block(&partial_input, 0)?;
                self.read_data_block(&mut partial_output, 0)?;
                output[..input.len()]
                    .copy_from_slice(&partial_output[block_index..block_index + input.len()]);
                self.zeroize_internal();
                return Ok(AesContext {
                    mode: CmAesMode::Ctr as u32,
                    key: *key,
                    last_ciphertext: iv,
                    last_block_index: (block_index + input.len()) as u8,
                    ..Default::default()
                });
            }

            partial_input[block_index..]
                .copy_from_slice(&input[..AES_BLOCK_SIZE_BYTES - block_index]);
            self.load_data_block(&partial_input, 0)?;
            self.read_data_block(&mut partial_output, 0)?;
            output[..AES_BLOCK_SIZE_BYTES - block_index]
                .copy_from_slice(&partial_output[block_index..]);

            input = &input[AES_BLOCK_SIZE_BYTES - block_index..];
            output = &mut output[AES_BLOCK_SIZE_BYTES - block_index..];

            iv = Self::add_iv(&iv, 1);

            // check if that was the last block
            if input.is_empty() {
                self.zeroize_internal();
                return Ok(AesContext {
                    mode: CmAesMode::Ctr as u32,
                    key: *key,
                    last_ciphertext: iv,
                    last_block_index: 0,
                    ..Default::default()
                });
            }
        }

        let num_blocks = input.len().div_ceil(AES_BLOCK_SIZE_BYTES);
        for i in 0..num_blocks - 1 {
            self.load_data_block(input, i)?;
            self.read_data_block(output, i)?;
        }

        // do the last block separately as it may be a partial block

        // checks needed to prevent panic
        if (num_blocks - 1) * AES_BLOCK_SIZE_BYTES >= input.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if (num_blocks - 1) * AES_BLOCK_SIZE_BYTES >= output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        let increment_iv = input.len() / AES_BLOCK_SIZE_BYTES;
        let input = &input[(num_blocks - 1) * AES_BLOCK_SIZE_BYTES..];
        let output = &mut output[(num_blocks - 1) * AES_BLOCK_SIZE_BYTES..];
        let mut last_input = [0u8; AES_BLOCK_SIZE_BYTES];
        let mut last_output = [0u8; AES_BLOCK_SIZE_BYTES];
        // checks needed to prevent panic
        if input.len() > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        if input.len() > output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        last_input[..input.len()].copy_from_slice(input);
        self.load_data_block(&last_input, 0)?;
        self.read_data_block(&mut last_output, 0)?;
        output[..input.len()].copy_from_slice(&last_output[..input.len()]);
        let iv = Self::add_iv(&iv, increment_iv as u32);
        self.zeroize_internal();
        Ok(AesContext {
            mode: CmAesMode::Ctr as u32,
            key: *key,
            last_ciphertext: iv,
            last_block_index: (input.len() % AES_BLOCK_SIZE_BYTES) as u8,
            ..Default::default()
        })
    }

    /// CMAC subkey generation, Algorithm 6.1 from NIST SP 800-38B.
    fn cmac_subkey_generation(&mut self, key: AesKey) -> CaliptraResult<(AesBlock, AesBlock)> {
        // sideload the KV key before we program the control register
        if key.sideload() {
            self.load_key(key)?;
        }

        self.with_aes(|aes, _| {
            wait_for_idle(&aes);
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Ecb as u32)
                        .operation(AesOperation::Encrypt as u32)
                        .manual_operation(false)
                        .sideload(key.sideload())
                });
            }
            wait_for_idle(&aes);
        });

        if !key.sideload() {
            self.load_key(key)?;
        }

        // 1. Let L = CIPH_K(0)
        self.load_data_block_u32(ZERO_BLOCK);
        let l: u128 = transmute!(self.read_data_block_u32());
        // convert to big-endian for shift register section
        let l = l.swap_bytes();

        // 2. If MSB1(L) == 0, then K1 = L << 1
        // Else K1 = (L << 1) XOR Rb

        // branchless LFSR
        let k1 = (l << 1) ^ ((l >> 127) * R_B);

        // 3. If MSB1(K1) == 0, then K2 = K1 << 1
        // Else K2 = (K1 << 1) XOR Rb
        let k2 = (k1 << 1) ^ ((k1 >> 127) * R_B);

        // convert back to native (little-endian)
        let k1 = k1.swap_bytes();
        let k2 = k2.swap_bytes();
        Ok((transmute!(k1), transmute!(k2)))
    }

    /// CMAC generation, Algorithm 6.2 from NIST SP 800-38B.
    pub fn cmac(&mut self, key: AesKey, message: &[u8]) -> CaliptraResult<AesBlock> {
        if message.len() > AES_MAX_DATA_SIZE {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }

        // 1. Apply the subkey generation process in Sec 6.1 to K to produce K1 and K2.
        // This generates the subkeys and also loads the key from the KV and sets the mode to ECB.
        let (k1, k2) = self.cmac_subkey_generation(key)?;

        // 2. If Mlen = 0, let n = 1; else, let n = ceil(Mlen / 128).
        let n = if message.is_empty() {
            1
        } else {
            message.len().div_ceil(AES_BLOCK_SIZE_BYTES)
        };

        // 3. Let M1, M2, ..., Mn* denote the unique sequence of bit strings such that M = M1 || M2 || ... || Mn*,
        // where M1, ..., Mn-1 are complete blocks.
        let mut m = message;
        // 5. Let C0 = 0^128.
        let mut c = AesBlock::default();
        for _ in 0..n {
            let mut input = [0u8; AES_BLOCK_SIZE_BYTES];
            let len = m.len().min(AES_BLOCK_SIZE_BYTES);
            input[..len].copy_from_slice(&m[..len]);
            if len < AES_BLOCK_SIZE_BYTES {
                input[len] = 0x80;
            }

            // 4. If Mn* is a complete block, let Mn = K1 XOR Mn*; else, let Mn = K2 XOR (Mn* || 10^j) where j = 128 - Mlen - 1.
            let mut input: AesBlock = transmute!(input);
            match m.len().cmp(&AES_BLOCK_SIZE_BYTES) {
                Ordering::Equal => {
                    for i in 0..AES_BLOCK_SIZE_WORDS {
                        input.0[i] ^= k1.0[i];
                    }
                }
                Ordering::Less => {
                    for i in 0..AES_BLOCK_SIZE_WORDS {
                        input.0[i] ^= k2.0[i];
                    }
                }
                _ => (), // not the last block, so do nothing
            }

            // 6. For i = 1 to n, let Ci = CIPH_K(C_i-1 XOR M_i)
            for i in 0..AES_BLOCK_SIZE_WORDS {
                input.0[i] ^= c.0[i];
            }
            self.load_data_block_u32(input);
            c = self.read_data_block_u32();
            m = &m[m.len().min(AES_BLOCK_SIZE_BYTES)..];
        }

        self.zeroize_internal();
        Ok(c)
    }

    /// Zeroize the non-GHASH hardware registers.
    fn zeroize_iv_data(&mut self) {
        self.with_aes(|aes, _| {
            // Disable autostarting the engine.
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| w.manual_operation(true));
            }
            // Clear IV, keys, input, output registers.
            aes.trigger()
                .write(|w| w.key_iv_data_in_clear(true).data_out_clear(true));
        });
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.zeroize_iv_data();
    }

    /// Zeroize the hardware registers.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// The caller must be certain that the results of any pending cryptographic
    /// operations will not be used after this function is called.
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn zeroize() {
        let aes = AesReg::new();
        let aes_clp = AesClpReg::new();
        Aes::new(aes, aes_clp).zeroize_internal();
    }
}
