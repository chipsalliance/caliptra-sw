/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for SHA-256 Cryptography operations

--*/

use core::{marker::PhantomData, usize};

use crate::{ Array4x8, CaliptraError, CaliptraResult, FortimacRegSteal};

use fortimac_hal::{FortimacErr, Fortimac256};
pub use fortimac_hal::{FortimacPeriph as Sha256Periph, FortimacReg as Sha256Reg};

// TODO: Fortimac requires seed, consider replacing with prng
const SEED: u32 = 0;
const SHA256_MAX_DATA_SIZE: usize = 1024 * 1024;

pub trait Sha256DigestOp<'a> {
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()>;
    fn update_wntz(&mut self, data: &[u8], w_value: u8, n_mode: bool) -> CaliptraResult<()>;
    /// # Arguments
    ///
    /// * `digest`  - result of the sha256 digest operation
    fn finalize(self, digest: &mut Array4x8) -> CaliptraResult<()>;
    /// # Arguments
    ///
    /// * `digest`  - result of the sha256 digest operation
    /// * `w_value` - Winternitz W value.
    /// * `n_mode`  - Winternitz n value(SHA192/SHA256 --> n = 24/32)
    fn finalize_wntz(self, digest: &mut Array4x8, w_value: u8, n_mode: bool) -> CaliptraResult<()>;
}

pub trait Sha256Alg {
    type DigestOp<'a>: Sha256DigestOp<'a>
    where
        Self: 'a;

    fn digest_init(&mut self) -> CaliptraResult<Self::DigestOp<'_>>;
    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8>;
}

pub struct Sha256 {
    sha256: Sha256Reg,
}

impl Sha256 {
    pub fn new(sha256: Sha256Reg) -> Self {
        Self { sha256 }
    }
}

impl Sha256Alg for Sha256 {
    type DigestOp<'a> = Sha256DigestOpHw<'a>;

    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha256Digest` - Object representing the digest operation
    fn digest_init(&mut self) -> CaliptraResult<Sha256DigestOpHw<'_>> {
        let engine = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);
        let op = Sha256DigestOpHw {
            _marker: PhantomData,
            sha: engine,
            data_size: 0,
        };

        Ok(op)
    }

    /// Calculate the digest of the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the digest over
    fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x8> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::SHA256_DIGEST_FAILURE)?
        }

        // Check if the buffer is not large
        if buf.len() > SHA256_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA256_MAX_DATA);
        }

        let sha = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);

        let mut digest = [0; 32];
        sha.digest(buf, &mut digest).map_err(|err| err.into_caliptra_err())?;

        #[cfg(feature = "fips-test-hooks")]
        let digest = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::SHA256_CORRUPT_DIGEST,
                &digest,
            )
        };

        self.zeroize_internal();

        Ok(Array4x8::from(digest))
    }
}
impl Sha256 {
    /// Take a raw sha256 digest of 0 or more 64-byte blocks of memory. Unlike
    /// digest(), the each word is passed to the sha256 peripheral without
    /// byte-swapping to reverse the peripheral's big-endian words. This means the
    /// hash will be measured with the byte-swapped value of each word.
    ///
    /// # Safety
    ///
    /// The caller is responsible for ensuring that the safety requirements of
    /// [`core::ptr::read`] are valid for every value between `ptr.add(0)` and
    /// `ptr.add(n_blocks - 1)`.
    #[inline(always)]
    pub unsafe fn digest_blocks_raw(
        &mut self,
        mut ptr: *const [u32; 16],
        n_blocks: usize,
    ) -> CaliptraResult<Array4x8> {
        let mut sha = Fortimac256::new_sha(unsafe{Sha256Reg::steal()}, SEED);

        for _ in 0..n_blocks {
            let block = Self::words_to_bytes_64(ptr.read());

            sha.update(&block).map_err(|err| err.into_caliptra_err())?;

            ptr = ptr.wrapping_add(1);
        }

        let mut digest_bytes = [0; 32];
        sha.finalize(&mut digest_bytes).map_err(|err| err.into_caliptra_err())?;

        Ok(Array4x8::from(digest_bytes))
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        unsafe { self.sha256.cfg().write_with_zero(|w| w.srst().set_bit()) };
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
        let sha256 = Sha256Reg::steal();
        sha256.cfg().write_with_zero(|w| w.srst().set_bit());
    }

    /// Converts word array to byte array
    fn words_to_bytes_64(words: [u32; 16]) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (chunk, word) in bytes.chunks_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }

        bytes
    }
    /*

    /// Calculate the digest of the last block
    ///
    /// # Arguments
    ///
    /// * `slice` - Slice of buffer to digest
    /// * `first` - Flag indicating if this is the first buffer
    /// * `buf_size` - Total buffer size
    fn digest_partial_block(
        &mut self,
        slice: &[u8],
        first: bool,
        buf_size: usize,
    ) -> CaliptraResult<()> {
        /// Set block length
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA256_BLOCK_BYTE_SIZE]) {
            let bit_len = (buf_size as u64) << 3;
            block[SHA256_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; SHA256_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_SHA256_INDEX_OUT_OF_BOUNDS);
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA256_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.digest_block(&block, first)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA256_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.digest_block(&block, false)?;
        }

        Ok(())
    }

    /// Calculate the digest of the last block
    ///
    /// # Arguments
    ///
    /// * `slice` - Slice of buffer to digest
    /// * `first` - Flag indicating if this is the first buffer
    /// * `buf_size` - Total buffer size
    /// * `w_value` - Winternitz W value.
    /// * `n_mode`  - Winternitz n value(SHA192/SHA256 --> n = 24/32)
    fn digest_wntz_partial_block(
        &mut self,
        slice: &[u8],
        first: bool,
        buf_size: usize,
        w_value: u8,
        n_mode: bool,
    ) -> CaliptraResult<()> {
        /// Set block length
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA256_BLOCK_BYTE_SIZE]) {
            let bit_len = (buf_size as u64) << 3;
            block[SHA256_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; SHA256_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_SHA256_INDEX_OUT_OF_BOUNDS);
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA256_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.digest_wntz_block(&block, first, w_value, n_mode)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA256_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.digest_wntz_block(&block, false, w_value, n_mode)?;
        }

        Ok(())
    }

    /// Calculate digest of the full block
    ///
    /// # Arguments
    ///
    /// * `block`: Block to calculate the digest
    /// * `first` - Flag indicating if this is the first block
    fn digest_block(
        &mut self,
        block: &[u8; SHA256_BLOCK_BYTE_SIZE],
        first: bool,
    ) -> CaliptraResult<()> {
        let sha256 = self.sha256.regs_mut();
        Array4x16::from(block).write_to_reg(sha256.block());
        self.digest_op(first)
    }

    /// Calculate digest of the full block
    ///
    /// # Arguments
    ///
    /// * `block`: Block to calculate the digest
    /// * `first` - Flag indicating if this is the first block
    /// * `w_value` - Winternitz W value.
    /// * `n_mode`  - Winternitz n value(SHA192/SHA256 --> n = 24/32)
    fn digest_wntz_block(
        &mut self,
        block: &[u8; SHA256_BLOCK_BYTE_SIZE],
        first: bool,
        w_value: u8,
        n_mode: bool,
    ) -> CaliptraResult<()> {
        let sha256 = self.sha256.regs_mut();
        Array4x16::from(block).write_to_reg(sha256.block());
        self.digest_wntz_op(first, w_value, n_mode)
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first` - Flag indicating if this is the first block
    fn digest_op(&mut self, first: bool) -> CaliptraResult<()> {
        let sha256 = self.sha256.regs_mut();

        // Wait for the hardware to be ready
        wait::until(|| sha256.status().read().ready());

        sha256
            .ctrl()
            .write(|w| w.wntz_mode(false).mode(true).init(first).next(!first));

        // Wait for the digest operation to finish
        wait::until(|| sha256.status().read().valid());

        Ok(())
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first`   - Flag indicating if this is the first block
    /// * `w_value` - Winternitz W value.
    /// * `n_mode`  - Winternitz n value(SHA192/SHA256 --> n = 24/32)
    fn digest_wntz_op(&mut self, first: bool, w_value: u8, n_mode: bool) -> CaliptraResult<()> {
        let sha256 = self.sha256.regs_mut();

        // Wait for the hardware to be ready
        wait::until(|| sha256.status().read().ready());

        // Submit the first block
        sha256.ctrl().write(|w| {
            w.wntz_n_mode(n_mode)
                .wntz_w(w_value.into())
                .wntz_mode(true)
                .mode(true)
                .init(first)
                .next(!first)
        });

        // Wait for the digest operation to finish
        wait::until(|| sha256.status().read().valid());

        Ok(())
    }
}

/// SHA-256 Digest state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Sha256DigestState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
    */
}

/// Multi step SHA-256 digest operation
pub struct Sha256DigestOpHw<'a> {
    /// Keep the original behaviour
    _marker: PhantomData<&'a ()>,

    /// SHA-256 Engine
    sha: Fortimac256,

    /// Data size
    data_size: usize,
}

impl<'a> Sha256DigestOp<'a> for Sha256DigestOpHw<'a> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.data_size + data.len() > SHA256_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA256_MAX_DATA);
        }

        self.sha.update(data).map_err(|err| err.into_caliptra_err())?;

        Ok(())
    }

    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    /// * `w_value` - Winternitz W value.
    /// * `n_mode`  - Winternitz n value(SHA192/SHA256 --> n = 24/32)
    fn update_wntz(&mut self, data: &[u8], _w_value: u8, _n_mode: bool) -> CaliptraResult<()> {
        // if self.state == Sha256DigestState::Final {
        //     return Err(CaliptraError::DRIVER_SHA256_INVALID_STATE);
        // }

        // if self.data_size + data.len() > SHA256_MAX_DATA_SIZE {
        //     return Err(CaliptraError::DRIVER_SHA256_MAX_DATA);
        // }

        // for byte in data {
        //     self.data_size += 1;

        //     // PANIC-FREE: Following check optimizes the out of bounds
        //     // panic in indexing the `buf`
        //     if self.buf_idx >= self.buf.len() {
        //         return Err(CaliptraError::DRIVER_SHA256_INDEX_OUT_OF_BOUNDS);
        //     }

        //     // Copy the data to the buffer
        //     self.buf[self.buf_idx] = *byte;
        //     self.buf_idx += 1;

        //     // If the buffer is full calculate the digest of accumulated data
        //     if self.buf_idx == self.buf.len() {
        //         self.sha
        //             .digest_wntz_block(&self.buf, self.is_first(), w_value, n_mode)?;
        //         self.reset_buf_state();
        //     }
        // }

        // Ok(())
        Self::update(self, data)
    }

    /// Finalize the digest operations
    fn finalize(self, digest: &mut Array4x8) -> CaliptraResult<()> {
        let mut digest_bytes = [0; 32];
        self.sha.finalize(&mut digest_bytes).map_err(|err| err.into_caliptra_err())?;
        *digest = Array4x8::from(digest_bytes);

        Ok(())
    }

    /// Finalize the digest operations
    fn finalize_wntz(
        self,
        digest: &mut Array4x8,
        _w_value: u8,
        _n_mode: bool,
    ) -> CaliptraResult<()> {
        // if self.state == Sha256DigestState::Final {
        //     return Err(CaliptraError::DRIVER_SHA256_INVALID_STATE);
        // }

        // if self.buf_idx > self.buf.len() {
        //     return Err(CaliptraError::DRIVER_SHA256_INVALID_SLICE);
        // }

        // // Calculate the digest of the final block
        // let buf = &self.buf[..self.buf_idx];
        // self.sha.digest_wntz_partial_block(
        //     buf,
        //     self.is_first(),
        //     self.data_size,
        //     w_value,
        //     n_mode,
        // )?;

        // // Set the state of the operation to final
        // self.state = Sha256DigestState::Final;

        // // Copy digest
        // self.sha.copy_digest_to_buf(digest)?;

        // Ok(())
        Self::finalize(self, digest)
    }
}

/// SHA-256 Fortimac error trait
trait Sha256FortimacErr {
    fn into_caliptra_err(self) -> CaliptraError;
}

impl Sha256FortimacErr for FortimacErr {
    /// Convert Fortimac errors to Caliptra during processing
    fn into_caliptra_err(self) -> CaliptraError {
        match self {
            FortimacErr::InvalidState => CaliptraError::DRIVER_SHA256_INVALID_STATE,
            FortimacErr::DataProc => CaliptraError::DRIVER_SHA256_DATA_PROC,
            FortimacErr::FaultInj => CaliptraError::DRIVER_SHA256_FAULT_INJ,
        }
    }
}
