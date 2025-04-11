/*++

Licensed under the Apache-2.0 license.

File Name:

    aes.rs

Abstract:

    Driver for AES hardware operations.

--*/

use crate::Array4x8;
use crate::{CaliptraError, CaliptraResult, Trng};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::aes::AesReg;

const AES_BLOCK_SIZE_BYTES: usize = 16;
const AES_IV_SIZE_BYTES: usize = 12;
const AES_BLOCK_SIZE_WORDS: usize = AES_BLOCK_SIZE_BYTES / 4;
const AES_MAX_DATA_SIZE: usize = 1024 * 1024;

/// AES GCM IV
#[derive(Debug, Copy, Clone)]
pub enum AesIv {
    U96(u128),
    Random,
}

impl From<u128> for AesIv {
    /// Converts to this type from the input type.
    fn from(value: u128) -> Self {
        Self::U96(value)
    }
}

impl From<&[u8; 12]> for AesIv {
    /// Converts to this type from the input type.
    fn from(value: &[u8; 12]) -> Self {
        let mut pad = [0u8; 16];
        pad[0..12].copy_from_slice(value);
        Self::U96(u128::from_le_bytes(pad))
    }
}

/// AES Key
#[derive(Debug, Copy, Clone)]
pub enum AesKey<'a> {
    /// Array - 32 Bytes (256 bits)
    Array4x8(&'a Array4x8),

    /// Split key parts that are XOR'd together
    Split(&'a Array4x8, &'a Array4x8),
}

impl<'a> From<&'a Array4x8> for AesKey<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a Array4x8) -> Self {
        Self::Array4x8(value)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AesMode {
    _Ecb = 1 << 0,
    _Cbc = 1 << 1,
    _Cfb = 1 << 2,
    _Ofb = 1 << 4,
    _Ctr = 1 << 5,
    Gcm = 1 << 6,
    _None = (1 << 7) - 1,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AesKeyLen {
    _128 = 1,
    _192 = 2,
    _256 = 4,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AesOperation {
    Encrypt = 1,
    Decrypt = 2,
}

pub enum GcmPhase {
    Init = 1 << 0,
    _Restore = 1 << 1,
    Aad = 1 << 2,
    Text = 1 << 3,
    _Save = 1 << 4,
    Tag = 1 << 5,
}

/// AES cryptographic engine driver.
pub struct Aes {
    aes: AesReg,
}

// the value of this mask is not important, but the AES engine must be programmed
// with the key split into two pieces that are XOR'd together.
const MASK: u32 = 0x1234_5678;

#[allow(clippy::too_many_arguments)]
impl Aes {
    pub fn new(aes: AesReg) -> Self {
        Self { aes }
    }

    fn with_aes<T>(
        &mut self,
        f: impl FnOnce(caliptra_registers::aes::RegisterBlock<ureg::RealMmioMut<'_>>) -> T,
    ) -> T {
        let aes = self.aes.regs_mut();
        f(aes)
    }

    /// Calculate the AES-256-GCM encrypted ciphertext for the given plaintext.
    /// Returns the IV and the tag.
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn aes_256_gcm_encrypt(
        &mut self,
        trng: &mut Trng,
        iv: AesIv,
        key: AesKey,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag_size: usize,
    ) -> CaliptraResult<([u8; AES_IV_SIZE_BYTES], [u8; AES_BLOCK_SIZE_BYTES])> {
        if tag_size > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG_SIZE)?;
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
        if tag.len() > AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG_SIZE)?;
        }
        let (_, _computed_tag) = self.aes_256_gcm_op(
            trng,
            AesIv::from(iv),
            key,
            aad,
            ciphertext,
            plaintext,
            AesOperation::Decrypt,
        )?;
        // TODO: check the tag
        Ok(())
    }

    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    fn aes_256_gcm_op(
        &mut self,
        trng: &mut Trng,
        iv: AesIv,
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

        if matches!(op, AesOperation::Decrypt) && matches!(iv, AesIv::Random) {
            // should be impossible
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_STATE)?;
        }
        let iv = match iv {
            AesIv::U96(iv) => [(iv >> 64) as u32, (iv >> 32) as u32, iv as u32],
            AesIv::Random => trng.generate()?.0[0..3].try_into().unwrap(),
        };

        let mut iv_return = [0u8; AES_IV_SIZE_BYTES];

        self.with_aes(|aes| {
            if !aes.status().read().idle() {
                Err(CaliptraError::RUNTIME_DRIVER_AES_ENGINE_BUSY)?;
            }

            // 1. Program the control register twice (since it is shadowed).
            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Gcm as u32)
                        .operation(op as u32)
                });
            }
            // 2. Program the GCM control register twice (since it is shadowed).
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Init as u32));
            }

            // 3. Program the key
            match key {
                AesKey::Array4x8(&arr) => {
                    for i in 0..arr.0.len() {
                        aes.key_share0().at(i).write(|_| arr.0[i] ^ MASK);
                        aes.key_share1().at(i).write(|_| MASK);
                    }
                }
                AesKey::Split(&key1, &key2) => {
                    for i in 0..key1.0.len() {
                        aes.key_share0().at(i).write(|_| key1.0[i]);
                        aes.key_share1().at(i).write(|_| key2.0[i]);
                    }
                }
            }

            // 4. Program the IV (last 4 bytes must be 0).
            for i in 0..3 {
                aes.iv().at(i).write(|_| iv[i]);
                iv_return[i * 4..i * 4 + 4].copy_from_slice(&iv[i].to_be_bytes());
            }
            aes.iv().at(3).write(|_| 0);

            // 5. Set the mode to AAD.
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Aad as u32));
            }
            Ok::<(), CaliptraError>(())
        })?;

        // 6. Load the AAD
        self.load_data(aad)?;

        self.with_aes(|aes| {
            // 7. Set the mode to text.
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Text as u32));
            }
        });

        // 8. Write blocks of plaintext and read blocks of ciphertext out.
        for start in (0..input.len()).step_by(AES_BLOCK_SIZE_BYTES) {
            let end = (start + AES_BLOCK_SIZE_BYTES).min(input.len());
            self.load_data_block(&input[start..end])?;
            if end - start < AES_BLOCK_SIZE_BYTES {
                self.set_gcm_len(end - start)?;
            }
            self.read_data_block(&mut output[start..end])?;
        }

        self.with_aes(|aes| {
            // 9. Set the mode to tag.
            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Tag as u32));
            }
        });

        // 10. Compute the final block and load it into data_in
        let mut tag_input = [0u8; AES_BLOCK_SIZE_BYTES];
        tag_input[0..8].copy_from_slice(&(aad.len() as u64).to_be_bytes());
        tag_input[8..16].copy_from_slice(&(input.len() as u64).to_be_bytes());
        self.load_data_block(&tag_input)?;

        // 11. Read out the tag.
        let mut tag_return = [0u8; AES_BLOCK_SIZE_BYTES];
        self.read_data_block(&mut tag_return)?;

        self.zeroize_internal();
        Ok((iv_return, tag_return))
    }

    fn read_data_block(&mut self, output: &mut [u8]) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();

        let mut buffer = [0u8; 16];

        while !aes.status().read().output_valid() {}

        // read the data out
        for i in 0..AES_BLOCK_SIZE_WORDS {
            buffer[i * 4..i * 4 + 4].copy_from_slice(&aes.data_out().at(i).read().to_le_bytes());
        }

        let len = output.len().min(buffer.len());
        output.copy_from_slice(&buffer[..len]);
        Ok(())
    }

    fn load_data_block(&mut self, data: &[u8]) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();

        while !aes.status().read().input_ready() {}
        let mut padded_data = [0u8; AES_BLOCK_SIZE_BYTES];
        let len = data.len().min(AES_BLOCK_SIZE_BYTES);
        padded_data[..len].copy_from_slice(&data[..len]);
        for (i, chunk) in padded_data.chunks(4).enumerate() {
            let word = u32::from_be_bytes(chunk.try_into().unwrap());
            aes.data_in().at(i).write(|_| word);
        }

        Ok(())
    }

    fn set_gcm_len(&mut self, len: usize) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();
        // wait for the engine to be idle
        while !aes.status().read().idle() {}
        // program the number of bytes for this block
        for _ in 0..2 {
            aes.ctrl_gcm_shadowed()
                .write(|w| w.num_valid_bytes(len as u32));
        }
        Ok(())
    }

    fn load_data(&mut self, mut aad: &[u8]) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();

        // wait for input ready to be set
        while !aes.status().read().input_ready() {}

        if aad.is_empty() {
            self.set_gcm_len(0)?;
            self.load_data_block(aad)?;
            return Ok(());
        }

        while !aad.is_empty() {
            let len = aad.len().min(AES_BLOCK_SIZE_BYTES);
            self.set_gcm_len(len)?;
            self.load_data_block(&aad[..len])?;
            aad = &aad[len..];
        }

        Ok(())
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        Self::zeroize_regs(&mut self.aes);
    }

    /// Helper function to zeroize the hardware registers.
    fn zeroize_regs(aes: &mut AesReg) {
        let aes = aes.regs_mut();
        // Disable autostarting the engine.
        for _ in 0..2 {
            aes.ctrl_shadowed().write(|w| w.manual_operation(true));
        }
        // Clear IV, keys, input, output registers.
        aes.trigger()
            .write(|w| w.key_iv_data_in_clear(true).data_out_clear(true));
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
        let mut aes = AesReg::new();
        Self::zeroize_regs(&mut aes);
    }
}
