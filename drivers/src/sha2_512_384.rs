/*++

Licensed under the Apache-2.0 license.

File Name:

    sha2_512_384.rs

Abstract:

    File contains API for SHA2-512/384 Cryptography operations

--*/

use core::usize;

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::PcrId;
use crate::{array::Array4x32, wait, Array4x12, Array4x16, Array4x8};
#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_registers::sha512::Sha512Reg;

// Block size, block length offset and max data size are same for both SHA2-384 and SHA2-512.
const SHA512_BLOCK_BYTE_SIZE: usize = 128;
const SHA512_BLOCK_LEN_OFFSET: usize = 112;
const SHA512_MAX_DATA_SIZE: usize = 1024 * 1024;
const SHA384_HASH_SIZE: usize = 48;

#[derive(Copy, Clone)]
pub enum ShaMode {
    Sha384,
    Sha512,
}

impl ShaMode {
    fn reg_value(&self) -> u32 {
        match self {
            Self::Sha384 => 0b10,
            Self::Sha512 => 0b11,
        }
    }
}

/// SHA-384 Digest
pub type Sha384Digest<'a> = &'a mut Array4x12;

pub struct Sha2_512_384 {
    sha512: Sha512Reg,
}

impl Sha2_512_384 {
    pub fn new(sha512: Sha512Reg) -> Self {
        Self { sha512 }
    }
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha2DigestOp` - Object representing the digest operation
    pub fn sha384_digest_init(&mut self) -> CaliptraResult<Sha2DigestOp<'_, Sha384>> {
        let op = Sha2DigestOp {
            sha: self,
            state: Sha2DigestState::Init,
            buf: [0u8; SHA512_BLOCK_BYTE_SIZE],
            buf_idx: 0,
            data_size: 0,
            _phantom: core::marker::PhantomData,
        };

        Ok(op)
    }

    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha2DigestOp` - Object representing the digest operation
    pub fn sha512_digest_init(&mut self) -> CaliptraResult<Sha2DigestOp<'_, Sha512>> {
        let op = Sha2DigestOp {
            sha: self,
            state: Sha2DigestState::Init,
            buf: [0u8; SHA512_BLOCK_BYTE_SIZE],
            buf_idx: 0,
            data_size: 0,
            _phantom: core::marker::PhantomData,
        };

        Ok(op)
    }

    fn sha_digest_helper(&mut self, buf: &[u8], mode: ShaMode) -> CaliptraResult<()> {
        #[cfg(feature = "fips-test-hooks")]
        unsafe {
            crate::FipsTestHook::error_if_hook_set(crate::FipsTestHook::SHA384_DIGEST_FAILURE)?
        }

        // Check if the buffer is not large
        if buf.len() > SHA512_MAX_DATA_SIZE {
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
                        self.digest_partial_block(mode, slice, first, buf.len())?;
                        break;
                    } else {
                        return Err(CaliptraError::DRIVER_SHA2_INVALID_SLICE);
                    }
                }
                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic call.
                    if let Some(slice) = buf.get(offset..offset + SHA512_BLOCK_BYTE_SIZE) {
                        let block = <&[u8; SHA512_BLOCK_BYTE_SIZE]>::try_from(slice).unwrap();
                        self.digest_block(mode, block, first, false)?;
                        bytes_remaining -= SHA512_BLOCK_BYTE_SIZE;
                        first = false;
                    } else {
                        return Err(CaliptraError::DRIVER_SHA2_INVALID_SLICE);
                    }
                }
            }
        }
        Ok(())
    }

    /// Calculate the SHA2-384 digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha384_digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x12> {
        self.sha_digest_helper(buf, ShaMode::Sha384)?;

        let digest = self.sha384_read_digest();

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

    /// Calculate the SHA2-512 digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn sha512_digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x16> {
        self.sha_digest_helper(buf, ShaMode::Sha512)?;

        wait::until(|| self.sha512.regs().status().read().valid());
        let digest = Array4x16::read_from_reg(self.sha512.regs().digest());

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
    fn sha384_read_digest(&mut self) -> Array4x12 {
        let sha = self.sha512.regs();
        // digest_block() only waits until the peripheral is ready for the next
        // command; the result register may not be valid yet
        wait::until(|| sha.status().read().valid());
        Array4x12::read_from_reg(sha.digest().truncate::<12>())
    }

    /// Copy digest to buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Digest buffer
    fn sha512_read_digest(&mut self) -> Array4x16 {
        let sha = self.sha512.regs();
        // digest_block() only waits until the peripheral is ready for the next
        // command; the result register may not be valid yet
        wait::until(|| sha.status().read().valid());
        Array4x16::read_from_reg(sha.digest())
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
        if total_bytes > (SHA512_BLOCK_BYTE_SIZE - 1) {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        // Wait on the PCR to be retrieved from the PCR vault.
        self.retrieve_pcr(id)?;

        // Prepare the data block; first SHA384_HASH_SIZE bytes are not filled
        // to account for the PCR retrieved. The retrieved PCR is unaffected as
        // writing to the first SHA384_HASH_SIZE bytes is skipped by the hardware.
        let mut block = [0u8; SHA512_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if SHA384_HASH_SIZE > total_bytes || total_bytes > block.len() {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }
        block[SHA384_HASH_SIZE..total_bytes].copy_from_slice(data);

        if let Some(slice) = block.get(..total_bytes) {
            self.digest_partial_block(ShaMode::Sha384, slice, true, total_bytes)?;
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
        mode: ShaMode,
        slice: &[u8],
        first: bool,
        buf_size: usize,
    ) -> CaliptraResult<()> {
        /// Set block length
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA512_BLOCK_BYTE_SIZE]) {
            let bit_len = (buf_size as u128) << 3;
            block[SHA512_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; SHA512_BLOCK_BYTE_SIZE];
        let mut last = false;

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_SHA384_INDEX_OUT_OF_BOUNDS);
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA512_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
            last = true;
        }

        // Calculate the digest of the op
        self.digest_block(mode, &block, first, last)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA512_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.digest_block(mode, &block, false, true)?;
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
        mode: ShaMode,
        block: &[u8; SHA512_BLOCK_BYTE_SIZE],
        first: bool,
        last: bool,
    ) -> CaliptraResult<()> {
        let sha512 = self.sha512.regs_mut();
        Array4x32::from(block).write_to_reg(sha512.block());
        self.digest_op(mode, first, last)
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first` - Flag indicating if this is the first block
    /// * `last` - Flag indicating if this is the last block
    fn digest_op(&mut self, mode: ShaMode, first: bool, last: bool) -> CaliptraResult<()> {
        let sha = self.sha512.regs_mut();

        // Wait for the hardware to be ready
        wait::until(|| sha.status().read().ready());

        // Submit the first/next block for hashing.
        sha.ctrl()
            .write(|w| w.mode(mode.reg_value()).init(first).next(!first).last(last));

        // Wait for the digest operation to finish
        wait::until(|| sha.status().read().ready());

        Ok(())
    }
}

/// SHA-384 Digest state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Sha2DigestState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// Multi step SHA-384 digest operation
pub struct Sha2DigestOp<'a, V> {
    /// SHA-384 Engine
    sha: &'a mut Sha2_512_384,

    /// State
    state: Sha2DigestState,

    /// Staging buffer
    buf: [u8; SHA512_BLOCK_BYTE_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,

    /// Phantom data to use the type parameter
    _phantom: core::marker::PhantomData<V>,
}

impl<'a, V: Sha2Variant> Sha2DigestOp<'a, V> {
    /// Check if this the first digest operation
    fn is_first(&self) -> bool {
        self.state == Sha2DigestState::Init
    }

    /// Reset internal buffer state
    fn reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Sha2DigestState::Pending;
    }
}

impl<'a> Sha2DigestOpTrait<'a, Sha384> for Sha2DigestOp<'a, Sha384> {
    fn as_digest_op(&mut self) -> &mut Sha2DigestOp<'a, Sha384> {
        self
    }
}

impl<'a> Sha2DigestOpTrait<'a, Sha512> for Sha2DigestOp<'a, Sha512> {
    fn as_digest_op(&mut self) -> &mut Sha2DigestOp<'a, Sha512> {
        self
    }
}

/// Trait for SHA-2 digest operations
pub trait Sha2DigestOpTrait<'a, V: Sha2Variant>: Sized {
    /// Get mutable reference to internal state
    fn as_digest_op(&mut self) -> &mut Sha2DigestOp<'a, V>;

    /// Update the digest with data
    fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        let this = self.as_digest_op();
        if this.state == Sha2DigestState::Final {
            return Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR);
        }

        if this.data_size + data.len() > SHA512_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_SHA384_MAX_DATA_ERR);
        }

        for byte in data {
            this.data_size += 1;

            if this.buf_idx >= this.buf.len() {
                return Err(CaliptraError::DRIVER_SHA384_INDEX_OUT_OF_BOUNDS);
            }

            this.buf[this.buf_idx] = *byte;
            this.buf_idx += 1;

            if this.buf_idx == this.buf.len() {
                this.sha
                    .digest_block(V::sha_mode(), &this.buf, this.is_first(), false)?;
                this.reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operation
    fn finalize(mut self, digest: &mut V::DigestType) -> CaliptraResult<()>
    where
        Self: Sized,
    {
        let this = self.as_digest_op();
        if this.state == Sha2DigestState::Final {
            return Err(CaliptraError::DRIVER_SHA384_INVALID_STATE_ERR);
        }

        if this.buf_idx > this.buf.len() {
            return Err(CaliptraError::DRIVER_SHA2_INVALID_SLICE);
        }

        let buf = &this.buf[..this.buf_idx];
        this.sha
            .digest_partial_block(V::sha_mode(), buf, this.is_first(), this.data_size)?;

        this.state = Sha2DigestState::Final;
        *digest = V::read_digest(this.sha);

        Ok(())
    }
}

/// Trait for SHA-2 variants defining their specific behaviors
pub trait Sha2Variant {
    /// The digest type for this SHA-2 variant
    type DigestType;

    /// Get the SHA mode for this variant
    fn sha_mode() -> ShaMode;

    /// Read the digest from hardware
    fn read_digest(sha: &mut Sha2_512_384) -> Self::DigestType;
}

/// SHA-384 variant implementation
pub struct Sha384;

impl Sha2Variant for Sha384 {
    type DigestType = Array4x12;

    fn sha_mode() -> ShaMode {
        ShaMode::Sha384
    }

    fn read_digest(sha: &mut Sha2_512_384) -> Self::DigestType {
        sha.sha384_read_digest()
    }
}

/// SHA-512 variant implementation
pub struct Sha512;

impl Sha2Variant for Sha512 {
    type DigestType = Array4x16;

    fn sha_mode() -> ShaMode {
        ShaMode::Sha512
    }

    fn read_digest(sha: &mut Sha2_512_384) -> Self::DigestType {
        sha.sha512_read_digest()
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
