/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384.rs

Abstract:

    File contains API for SHA-384 Cryptography operations

--*/

use core::usize;

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::PcrId;
use crate::{array::Array4x32, wait, Array4x12, Array4x8};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::sha512::Sha512Reg;

const SHA384_BLOCK_BYTE_SIZE: usize = 128;
const SHA384_BLOCK_LEN_OFFSET: usize = 112;
const SHA384_MAX_DATA_SIZE: usize = 1024 * 1024;
const SHA384_HASH_SIZE: usize = 48;

/// SHA-384 Digest
pub type Sha384Digest<'a> = &'a mut Array4x12;

pub struct Sha384 {
    sha512: Sha512Reg,
}

impl Sha384 {
    pub fn new(sha512: Sha512Reg) -> Self {
        Self { sha512 }
    }
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha384Digest` - Object representing the digest operation
    pub fn digest_init(&mut self) -> CaliptraResult<Sha384DigestOp<'_>> {
        let op = Sha384DigestOp {
            sha: self,
            state: Sha384DigestState::Init,
            buf: [0u8; SHA384_BLOCK_BYTE_SIZE],
            buf_idx: 0,
            data_size: 0,
        };

        Ok(op)
    }

    /// Calculate the digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x12> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::SHA384_DIGEST_FAILURE)?
        }

        // Check if the buffer is not large
        if buf.len() > SHA384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        let mut first = true;
        let mut bytes_remaining = buf.len();

        loop {
            let offset = buf.len() - bytes_remaining;
            match bytes_remaining {
                0..=127 => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic.
                    if let Some(slice) = buf.get(offset..) {
                        self.digest_partial_block(slice, first, buf.len())?;
                        break;
                    } else {
                        return Err(CaliptraError::DRIVER_SHA384_INVALID_SLICE);
                    }
                }
                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic call.
                    if let Some(slice) = buf.get(offset..offset + SHA384_BLOCK_BYTE_SIZE) {
                        let block = <&[u8; SHA384_BLOCK_BYTE_SIZE]>::try_from(slice).unwrap();
                        self.digest_block(block, first, false)?;
                        bytes_remaining -= SHA384_BLOCK_BYTE_SIZE;
                        first = false;
                    } else {
                        return Err(CaliptraError::DRIVER_SHA384_INVALID_SLICE);
                    }
                }
            }
        }
        let digest = self.read_digest();

        #[cfg(feature = "fips-test-hooks")]
        let digest = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::SHA384_CORRUPT_DIGEST,
                &digest,
            )
        };

        self.zeroize_internal();

        Ok(digest)
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.sha512.regs_mut().ctrl().write(|w| w.zeroize(true));
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
        let mut sha384 = Sha512Reg::new();
        sha384.regs_mut().ctrl().write(|w| w.zeroize(true));
    }

    /// Copy digest to buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Digest buffer
    fn read_digest(&mut self) -> Array4x12 {
        let sha = self.sha512.regs();
        // digest_block() only waits until the peripheral is ready for the next
        // command; the result register may not be valid yet
        wait::until(|| sha.status().read().valid());
        Array4x12::read_from_reg(sha.digest().truncate::<12>())
    }

    /// Generate digest over PCRs + nonce
    ///
    /// # Arguments
    ///
    /// * `nonce`- Nonce buffer
    ///
    /// # Returns
    ///
    /// * `buf` - Digest buffer
    pub fn gen_pcr_hash(&mut self, nonce: Array4x8) -> CaliptraResult<Array4x12> {
        let reg = self.sha512.regs_mut();
        let status_reg = reg.gen_pcr_hash_status();

        // Wait for the registers to be ready
        wait::until(|| status_reg.read().ready());

        // Write the nonce into the register
        reg.gen_pcr_hash_nonce().write(&nonce.into());

        // Use the start command to start the digesting process
        reg.gen_pcr_hash_ctrl().write(|ctrl| ctrl.start(true));

        // Wait for the registers to be ready
        wait::until(|| status_reg.read().ready());

        // Initialize SHA hardware to clear write lock
        reg.ctrl().write(|w| w.init(true));
        wait::until(|| status_reg.read().ready());

        if status_reg.read().valid() {
            Ok(reg.gen_pcr_hash_digest().read().into())
        } else {
            Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR)
        }
    }

    pub fn pcr_extend(&mut self, id: PcrId, data: &[u8]) -> CaliptraResult<()> {
        let total_bytes = data.len() + SHA384_HASH_SIZE;
        if total_bytes > (SHA384_BLOCK_BYTE_SIZE - 1) {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        // Wait on the PCR to be retrieved from the PCR vault.
        self.retrieve_pcr(id)?;

        // Prepare the data block; first SHA384_HASH_SIZE bytes are not filled
        // to account for the PCR retrieved. The retrieved PCR is unaffected as
        // writing to the first SHA384_HASH_SIZE bytes is skipped by the hardware.
        let mut block = [0u8; SHA384_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if SHA384_HASH_SIZE > total_bytes || total_bytes > block.len() {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }
        block[SHA384_HASH_SIZE..total_bytes].copy_from_slice(data);

        if let Some(slice) = block.get(..total_bytes) {
            self.digest_partial_block(slice, true, total_bytes)?;
        } else {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        Ok(())
    }

    /// Waits for the PCR to be retrieved from the PCR vault
    /// and copied to the block registers.
    ///
    /// # Arguments
    ///
    /// * `pcr_id` - PCR to hash extend
    fn retrieve_pcr(&mut self, pcr_id: PcrId) -> CaliptraResult<()> {
        let sha = self.sha512.regs_mut();

        KvAccess::extend_from_pv(pcr_id, sha.vault_rd_status(), sha.vault_rd_ctrl())
            .map_err(|err| err.into_read_data_err())?;

        Ok(())
    }

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
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA384_BLOCK_BYTE_SIZE]) {
            let bit_len = (buf_size as u128) << 3;
            block[SHA384_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; SHA384_BLOCK_BYTE_SIZE];
        let mut last = false;

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_SHA384_INDEX_OUT_OF_BOUNDS);
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA384_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
            last = true;
        }

        // Calculate the digest of the op
        self.digest_block(&block, first, last)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA384_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.digest_block(&block, false, true)?;
        }

        Ok(())
    }

    /// Calculate digest of the full block
    ///
    /// # Arguments
    ///
    /// * `block`: Block to calculate the digest
    /// * `first` - Flag indicating if this is the first block
    /// * `last` - Flag indicating if this is the last block
    fn digest_block(
        &mut self,
        block: &[u8; SHA384_BLOCK_BYTE_SIZE],
        first: bool,
        last: bool,
    ) -> CaliptraResult<()> {
        let sha512 = self.sha512.regs_mut();
        Array4x32::from(block).write_to_reg(sha512.block());
        self.digest_op(first, last)
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first` - Flag indicating if this is the first block
    /// * `last` - Flag indicating if this is the last block
    fn digest_op(&mut self, first: bool, last: bool) -> CaliptraResult<()> {
        const MODE_SHA384: u32 = 0b10;

        let sha = self.sha512.regs_mut();

        // Wait for the hardware to be ready
        wait::until(|| sha.status().read().ready());

        // Submit the first/next block for hashing.
        sha.ctrl()
            .write(|w| w.mode(MODE_SHA384).init(first).next(!first).last(last));

        // Wait for the digest operation to finish
        wait::until(|| sha.status().read().ready());

        Ok(())
    }
}

/// SHA-384 Digest state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Sha384DigestState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// Multi step SHA-384 digest operation
pub struct Sha384DigestOp<'a> {
    /// SHA-384 Engine
    sha: &'a mut Sha384,

    /// State
    state: Sha384DigestState,

    /// Staging buffer
    buf: [u8; SHA384_BLOCK_BYTE_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,
}

impl<'a> Sha384DigestOp<'a> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state == Sha384DigestState::Final {
            return Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR);
        }

        if self.data_size + data.len() > SHA384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        for byte in data {
            self.data_size += 1;

            // PANIC-FREE: Following check optimizes the out of bounds
            // panic in indexing the `buf`
            if self.buf_idx >= self.buf.len() {
                return Err(CaliptraError::DRIVER_SHA384_INDEX_OUT_OF_BOUNDS);
            }

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the digest of accumulated data
            if self.buf_idx == self.buf.len() {
                self.sha.digest_block(&self.buf, self.is_first(), false)?;
                self.reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(mut self, digest: &mut Array4x12) -> CaliptraResult<()> {
        if self.state == Sha384DigestState::Final {
            return Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR);
        }

        if self.buf_idx > self.buf.len() {
            return Err(CaliptraError::DRIVER_SHA384_INVALID_SLICE);
        }

        // Calculate the digest of the final block
        let buf = &self.buf[..self.buf_idx];
        self.sha
            .digest_partial_block(buf, self.is_first(), self.data_size)?;

        // Set the state of the operation to final
        self.state = Sha384DigestState::Final;

        // Copy digest
        *digest = self.sha.read_digest();

        Ok(())
    }

    /// Check if this the first digest operation
    fn is_first(&self) -> bool {
        self.state == Sha384DigestState::Init
    }

    /// Reset internal buffer state
    fn reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Sha384DigestState::Pending;
    }
}

/// SHA-384 key access error trait
trait Sha384KeyAccessErr {
    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError;
}

impl Sha384KeyAccessErr for KvAccessErr {
    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_SHA384_READ_DATA_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_SHA384_READ_DATA_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_SHA384_READ_DATA_KV_UNKNOWN,
        }
    }
}
