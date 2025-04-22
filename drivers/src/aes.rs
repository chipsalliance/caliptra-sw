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

use crate::{cprintln, kv_access::KvAccess, CaliptraError, CaliptraResult, KeyReadArgs, Trng};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::{aes::AesReg, aes_clp::AesClpReg};
use zerocopy::transmute;

const AES_BLOCK_SIZE_BYTES: usize = 16;
const AES_IV_SIZE_BYTES: usize = 12;
const AES_BLOCK_SIZE_WORDS: usize = AES_BLOCK_SIZE_BYTES / 4;
const AES_MAX_DATA_SIZE: usize = 1024 * 1024;

/// AES GCM IV
#[derive(Debug, Copy, Clone)]
pub enum AesIv<'a> {
    Array(&'a [u8; 12]),
    Random,
}

impl<'a> From<&'a [u8; 12]> for AesIv<'a> {
    fn from(value: &'a [u8; 12]) -> Self {
        Self::Array(value)
    }
}

/// AES Key
#[derive(Debug, Copy, Clone)]
pub enum AesKey<'a> {
    /// Array - 32 Bytes (256 bits)
    Array(&'a [u8; 32]),

    /// Split key parts that are XOR'd together
    Split(&'a [u8; 32], &'a [u8; 32]),

    /// Read from key vault
    Key(KeyReadArgs),
}

impl<'a> From<&'a [u8; 32]> for AesKey<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8; 32]) -> Self {
        Self::Array(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AesMode {
    _Ecb = 1 << 0,
    _Cbc = 1 << 1,
    _Cfb = 1 << 2,
    _Ofb = 1 << 3,
    _Ctr = 1 << 4,
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

/// Wait for the AES engine to be idle.
/// Necessary before writing control registers.
fn wait_for_idle(aes: &caliptra_registers::aes::RegisterBlock<ureg::RealMmioMut<'_>>) {
    while !aes.status().read().idle() {}
}

#[allow(clippy::too_many_arguments)]
impl Aes {
    pub fn new(aes: AesReg) -> Self {
        Self { aes }
    }

    // Ensures that only one copy of the AES registers are used
    // in any given context to ensure exclusive access.
    fn with_aes<T>(
        &mut self,
        f: impl FnOnce(caliptra_registers::aes::RegisterBlock<ureg::RealMmioMut<'_>>) -> T,
    ) -> T {
        let aes = self.aes.regs_mut();
        f(aes)
    }

    pub fn init_masking(&mut self, trng: &mut Trng) -> CaliptraResult<()> {
        self.with_aes(|_aes| {
            // always safe to reset the seed, even if the engine is busy
            let mut aes_clp = unsafe { AesClpReg::new() };
            let regs = aes_clp.regs_mut();
            let seed = trng.generate()?;
            const MASK_SIZE: usize = 9;
            for i in 0..MASK_SIZE {
                regs.entropy_if_seed().at(i).write(|_| seed.0[i]);
            }
            Ok(())
        })
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
        let (_, _computed_tag) = self.aes_256_gcm_op(
            trng,
            iv.into(),
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

        // No zerocopy since we can't guarantee that the
        // byte array is aligned to 4-byte boundaries.
        let iv = match iv {
            AesIv::Array(iv) => [
                u32::from_le_bytes(iv[0..4].try_into().unwrap()),
                u32::from_le_bytes(iv[4..8].try_into().unwrap()),
                u32::from_le_bytes(iv[8..12].try_into().unwrap()),
            ],
            AesIv::Random => trng.generate()?.0[0..3].try_into().unwrap(),
        };

        self.with_aes(|aes| {
            cprintln!("Wait for AES idle 1");
            wait_for_idle(&aes);
            cprintln!("Wait for AES idle 1 done");

            // sideload the KV key before we program the control register
            match key {
                AesKey::Key(key) => {
                    let mut aes_clp = unsafe { AesClpReg::new() };
                    let regs = aes_clp.regs_mut();
                    cprintln!("Copy from KV");
                    KvAccess::copy_from_kv(
                        key,
                        regs.aes_kv_rd_key_status(),
                        regs.aes_kv_rd_key_ctrl(),
                    )
                    .map_err(|_| CaliptraError::DRIVER_HMAC_READ_KEY_KV_READ)?;
                    cprintln!("Copy from KV done");
                }
                _ => (),
            }

            cprintln!("Wait for AES idle 2");
            wait_for_idle(&aes);
            cprintln!("Wait for AES idle 2 done");

            for _ in 0..2 {
                aes.ctrl_shadowed().write(|w| {
                    w.key_len(AesKeyLen::_256 as u32)
                        .mode(AesMode::Gcm as u32)
                        .operation(op as u32)
                        .manual_operation(false)
                        .sideload(matches!(key, AesKey::Key(_)))
                });
            }

            wait_for_idle(&aes);

            for _ in 0..2 {
                aes.ctrl_gcm_shadowed()
                    .write(|w| w.phase(GcmPhase::Init as u32).num_valid_bytes(16));
            }

            // Program the key
            // No zerocopy since we can't guarantee that the
            // byte arrays are aligned to 4-byte boundaries.
            match key {
                AesKey::Array(&arr) => {
                    for (i, chunk) in arr.chunks_exact(4).enumerate() {
                        let word = u32::from_le_bytes(chunk.try_into().unwrap());
                        aes.key_share0().at(i).write(|_| word ^ MASK);
                        aes.key_share1().at(i).write(|_| MASK);
                    }
                }
                AesKey::Split(&key1, &key2) => {
                    for (i, chunk) in key1.chunks_exact(4).enumerate() {
                        let word = u32::from_le_bytes(chunk.try_into().unwrap());
                        aes.key_share0().at(i).write(|_| word);
                    }
                    for (i, chunk) in key2.chunks_exact(4).enumerate() {
                        let word = u32::from_le_bytes(chunk.try_into().unwrap());
                        aes.key_share1().at(i).write(|_| word);
                    }
                }
                AesKey::Key(_) => (), // key is already sideloaded
            }

            cprintln!("Wait for AES idle 3");
            wait_for_idle(&aes);
            cprintln!("Wait for AES idle 3 done");
            // Program the IV (last 4 bytes must be 0).
            for (i, ivi) in iv.into_iter().enumerate() {
                aes.iv().at(i).write(|_| ivi);
            }
            aes.iv().at(3).write(|_| 0);

            Ok::<(), CaliptraError>(())
        })?;

        // Load the AAD
        cprintln!("Write AAD");
        if !aad.is_empty() {
            self.read_write_data(aad, GcmPhase::Aad, None)?;
        }

        cprintln!("RW blocks");
        // Write blocks of plaintext and read blocks of ciphertext out.
        self.read_write_data(input, GcmPhase::Text, Some(output))?;

        cprintln!("Compute tag");
        // Compute the tag
        self.with_aes(|aes| {
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
        tag_input[0..8].copy_from_slice(&((aad.len() * 8) as u64).to_be_bytes());
        tag_input[8..16].copy_from_slice(&((input.len() * 8) as u64).to_be_bytes());
        self.load_data_block(&tag_input, 0)?;

        // Read out the tag.
        let mut tag_return = [0u8; AES_BLOCK_SIZE_BYTES];
        self.read_data_block(&mut tag_return, 0)?;

        self.zeroize_internal();
        cprintln!("Done");
        Ok((transmute!(iv), tag_return))
    }

    fn read_data_block(&mut self, output: &mut [u8], block_num: usize) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();
        cprintln!("Wait on output valid {:x}", u32::from(aes.status().read()));
        while !aes.status().read().output_valid() {}
        cprintln!("Wait on output valid done");

        let mut buffer = [0u8; 16];
        // read the data out
        for i in 0..AES_BLOCK_SIZE_WORDS {
            let x = aes.data_out().at(i).read();
            buffer[i * 4..i * 4 + 4].copy_from_slice(&x.to_le_bytes());
        }

        // not possible but needed to prevent panic
        if block_num * AES_BLOCK_SIZE_BYTES >= output.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        let output = &mut output[block_num * AES_BLOCK_SIZE_BYTES..];
        let len = output.len().min(AES_BLOCK_SIZE_BYTES);
        let output = &mut output[..len];
        output[..len].copy_from_slice(&buffer[..len]);
        Ok(())
    }

    fn load_data_block(&mut self, data: &[u8], block_num: usize) -> CaliptraResult<()> {
        let aes = self.aes.regs_mut();

        // not possible but needed to prevent panic
        if block_num * AES_BLOCK_SIZE_BYTES >= data.len() {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        let data = &data[block_num * AES_BLOCK_SIZE_BYTES..];
        let data = &data[..AES_BLOCK_SIZE_BYTES.min(data.len())];

        cprintln!("Wait on input ready {:x}", u32::from(aes.status().read()));
        while !aes.status().read().input_ready() {}
        cprintln!("Wait on input ready done");
        let len = data.len();
        let mut padded_data = [0u8; AES_BLOCK_SIZE_BYTES];
        let data = if len < AES_BLOCK_SIZE_BYTES {
            padded_data[..len].copy_from_slice(&data[..len]);
            &padded_data[..]
        } else {
            data
        };
        // not possible but needed to prevent panic
        if data.len() != AES_BLOCK_SIZE_BYTES {
            Err(CaliptraError::RUNTIME_DRIVER_AES_INVALID_SLICE)?;
        }
        for (i, chunk) in data.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            aes.data_in().at(i).write(|_| word);
        }

        Ok(())
    }

    fn read_write_data(
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
                self.with_aes(|aes| {
                    cprintln!(
                        "RW wait for idle, status {:x}",
                        u32::from(aes.status().read())
                    );
                    wait_for_idle(&aes);
                    cprintln!("RW wait for idle done");
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

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        Self::zeroize_regs(&mut self.aes);
    }

    /// Helper function to zeroize the hardware registers.
    fn zeroize_regs(aes: &mut AesReg) {
        let aes = aes.regs_mut();

        wait_for_idle(&aes);

        // Disable autostarting the engine.
        for _ in 0..2 {
            aes.ctrl_shadowed().write(|w| w.manual_operation(true));
        }
        // Clear IV, keys, input, output registers.
        aes.trigger()
            .write(|w| w.key_iv_data_in_clear(true).data_out_clear(true));

        wait_for_idle(&aes);
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
