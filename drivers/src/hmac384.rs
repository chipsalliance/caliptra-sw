/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384.rs

Abstract:

    File contains API for HMAC-384 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array::Array4x32, wait, Array4x12, CaliptraError, CaliptraResult, KeyReadArgs, KeyWriteArgs,
    Trng,
};

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::hmac::HmacReg;
use core::usize;

const HMAC384_BLOCK_SIZE_BYTES: usize = 128;
const HMAC384_BLOCK_LEN_OFFSET: usize = 112;
const HMAC384_MAX_DATA_SIZE: usize = 1024 * 1024;

/// HMAC-384 Data
#[derive(Debug, Copy, Clone)]
pub enum Hmac384Data<'a> {
    /// Slice
    Slice(&'a [u8]),

    /// Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a [u8]> for Hmac384Data<'a> {
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Hmac384Data<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8; N]) -> Self {
        Self::Slice(value)
    }
}

impl From<KeyReadArgs> for Hmac384Data<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// Hmac-384 Tag
#[derive(Debug)]
pub enum Hmac384Tag<'a> {
    /// Array
    Array4x12(&'a mut Array4x12),

    /// Key output
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for Hmac384Tag<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<KeyWriteArgs> for Hmac384Tag<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

///
/// Hmac-384 Key
///
#[derive(Debug, Copy, Clone)]
pub enum Hmac384Key<'a> {
    /// Array
    Array4x12(&'a Array4x12),

    // Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a Array4x12> for Hmac384Key<'a> {
    ///
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl From<KeyReadArgs> for Hmac384Key<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

pub struct Hmac384 {
    hmac: HmacReg,
}

impl Hmac384 {
    pub fn new(hmac: HmacReg) -> Self {
        Self { hmac }
    }
    /// Initialize multi step HMAC operation
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `trng` - TRNG driver instance
    ///
    /// * `tag`  -  The calculated tag
    pub fn hmac_init<'a>(
        &'a mut self,
        key: &Hmac384Key,
        trng: &mut Trng,
        mut tag: Hmac384Tag<'a>,
    ) -> CaliptraResult<Hmac384Op> {
        let hmac = self.hmac.regs_mut();

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        match &mut tag {
            Hmac384Tag::Array4x12(_arr) => {
                KvAccess::begin_copy_to_arr(hmac.kv_wr_status(), hmac.kv_wr_ctrl())?
            }
            Hmac384Tag::Key(key) => {
                KvAccess::begin_copy_to_kv(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), *key)?
            }
        }

        // Configure the hardware to use key to use for the HMAC operation
        match key {
            Hmac384Key::Array4x12(arr) => KvAccess::copy_from_arr(arr, hmac.key())?,
            Hmac384Key::Key(key) => {
                KvAccess::copy_from_kv(*key, hmac.kv_rd_key_status(), hmac.kv_rd_key_ctrl())
                    .map_err(|err| err.into_read_key_err())?
            }
        }

        // Generate an LFSR seed and copy to key vault.
        self.gen_lfsr_seed(trng)?;

        let op = Hmac384Op {
            hmac_engine: self,
            state: Hmac384OpState::Init,
            buf: [0u8; HMAC384_BLOCK_SIZE_BYTES],
            buf_idx: 0,
            data_size: 0,
            tag,
        };

        Ok(op)
    }

    /// Generate an LFSR seed and copy to keyvault.
    ///
    /// # Arguments
    ///
    /// * `trng` - TRNG driver instance
    fn gen_lfsr_seed(&mut self, trng: &mut Trng) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        let rand_data = trng.generate()?;
        cfg_if::cfg_if! {
            if #[cfg(feature="hw-1.0")] {
                use crate::Array4x5;
                let iv: [u32; 5] = rand_data.0[..5].try_into().unwrap();
                KvAccess::copy_from_arr(&Array4x5::from(iv), hmac.lfsr_seed())?;
            } else {
                let iv: [u32; 12] = rand_data.0[..12].try_into().unwrap();
                KvAccess::copy_from_arr(&Array4x12::from(iv), hmac.lfsr_seed())?;
            }
        }
        Ok(())
    }

    /// Calculate the hmac for specified data
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `data` - Data to calculate the HMAC over
    /// * `trng` - TRNG driver instance
    ///
    /// * `tag`  -  The calculated tag
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn hmac(
        &mut self,
        key: &Hmac384Key,
        data: &Hmac384Data,
        trng: &mut Trng,
        tag: Hmac384Tag,
    ) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();
        let mut tag = tag;

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        match &mut tag {
            Hmac384Tag::Array4x12(_arr) => {
                KvAccess::begin_copy_to_arr(hmac.kv_wr_status(), hmac.kv_wr_ctrl())?
            }
            Hmac384Tag::Key(key) => {
                KvAccess::begin_copy_to_kv(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), *key)?
            }
        }

        // Configure the hardware to use key to use for the HMAC operation
        match key {
            Hmac384Key::Array4x12(arr) => KvAccess::copy_from_arr(arr, hmac.key())?,
            Hmac384Key::Key(key) => {
                KvAccess::copy_from_kv(*key, hmac.kv_rd_key_status(), hmac.kv_rd_key_ctrl())
                    .map_err(|err| err.into_read_key_err())?
            }
        }
        // Generate an LFSR seed and copy to key vault.
        self.gen_lfsr_seed(trng)?;

        // Calculate the hmac
        match data {
            Hmac384Data::Slice(buf) => self.hmac_buf(buf)?,
            Hmac384Data::Key(key) => self.hmac_key(*key)?,
        }
        let hmac = self.hmac.regs();

        // Copy the tag to the specified location
        let result = match &mut tag {
            Hmac384Tag::Array4x12(arr) => KvAccess::end_copy_to_arr(hmac.tag(), arr),
            Hmac384Tag::Key(key) => KvAccess::end_copy_to_kv(hmac.kv_wr_status(), *key)
                .map_err(|err| err.into_write_tag_err()),
        };

        self.zeroize_internal();

        result
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.hmac.regs_mut().ctrl().write(|w| w.zeroize(true));
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
        let mut hmac = HmacReg::new();
        hmac.regs_mut().ctrl().write(|w| w.zeroize(true));
    }

    ///
    /// Calculate the hmac of the buffer provided as parameter
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the hmac over
    ///
    fn hmac_buf(&mut self, buf: &[u8]) -> CaliptraResult<()> {
        // Check if the buffer is within the size that we support
        if buf.len() > HMAC384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_HMAC384_MAX_DATA);
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
                        self.hmac_partial_block(slice, first, buf.len())?;
                        break;
                    } else {
                        return Err(CaliptraError::DRIVER_HMAC384_INVALID_SLICE);
                    }
                }

                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic.
                    if let Some(slice) = buf.get(offset..offset + HMAC384_BLOCK_SIZE_BYTES) {
                        let block = <&[u8; HMAC384_BLOCK_SIZE_BYTES]>::try_from(slice).unwrap();
                        self.hmac_block(block, first)?;
                        bytes_remaining -= HMAC384_BLOCK_SIZE_BYTES;
                        first = false;
                    } else {
                        return Err(CaliptraError::DRIVER_HMAC384_INVALID_SLICE);
                    }
                }
            }
        }

        Ok(())
    }

    ///
    /// Calculate hmac of a key in the Key Vault
    ///
    /// # Arguments
    ///
    /// * `key` - Key to calculate hmac for
    ///
    fn hmac_key(&mut self, key: KeyReadArgs) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        KvAccess::copy_from_kv(key, hmac.kv_rd_block_status(), hmac.kv_rd_block_ctrl())
            .map_err(|err| err.into_read_data_err())?;

        self.hmac_op(true)
    }

    fn hmac_partial_block(
        &mut self,
        slice: &[u8],
        first: bool,
        buf_size: usize,
    ) -> CaliptraResult<()> {
        /// Set block length
        fn set_block_len(buf_size: usize, block: &mut [u8; HMAC384_BLOCK_SIZE_BYTES]) {
            let bit_len = ((buf_size + HMAC384_BLOCK_SIZE_BYTES) as u128) << 3;
            block[HMAC384_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; HMAC384_BLOCK_SIZE_BYTES];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_HMAC384_INDEX_OUT_OF_BOUNDS);
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < HMAC384_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.hmac_block(&block, first)?;

        // Add a padding block if one is needed
        if slice.len() >= HMAC384_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.hmac_block(&block, false)?;
        }

        Ok(())
    }

    ///
    /// Calculate digest of the full block
    ///
    /// # Arguments
    ///
    /// * `block`: Block to calculate the digest
    /// * `first` - Flag indicating if this is the first block
    ///
    fn hmac_block(
        &mut self,
        block: &[u8; HMAC384_BLOCK_SIZE_BYTES],
        first: bool,
    ) -> CaliptraResult<()> {
        let hmac384 = self.hmac.regs_mut();
        Array4x32::from(block).write_to_reg(hmac384.block());
        self.hmac_op(first)
    }

    ///
    /// Perform the hmac operation in the hardware
    ///
    /// # Arguments
    ///
    /// * `first` - Flag indicating if this is the first block
    ///
    fn hmac_op(&mut self, first: bool) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        // Wait for the hardware to be ready
        wait::until(|| hmac.status().read().ready());

        if first {
            // Submit the first block
            hmac.ctrl().write(|w| w.init(true).next(false));
        } else {
            // Submit next block in existing hashing chain
            hmac.ctrl().write(|w| w.init(false).next(true));
        }

        // Wait for the hmac operation to finish
        wait::until(|| hmac.status().read().valid());

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Hmac384OpState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// HMAC multi step operation
pub struct Hmac384Op<'a> {
    /// Hmac-384 Engine
    hmac_engine: &'a mut Hmac384,

    /// State
    state: Hmac384OpState,

    /// Staging buffer
    buf: [u8; HMAC384_BLOCK_SIZE_BYTES],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,

    /// Tag
    tag: Hmac384Tag<'a>,
}

impl<'a> Hmac384Op<'a> {
    ///
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state == Hmac384OpState::Final {
            return Err(CaliptraError::DRIVER_HMAC384_INVALID_STATE);
        }

        if self.data_size + data.len() > HMAC384_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_HMAC384_MAX_DATA);
        }

        for byte in data {
            self.data_size += 1;

            // PANIC-FREE: Following check optimizes the out of bounds
            // panic in indexing the `buf`
            if self.buf_idx >= self.buf.len() {
                return Err(CaliptraError::DRIVER_HMAC384_INDEX_OUT_OF_BOUNDS);
            }

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the digest of accumulated data
            if self.buf_idx == self.buf.len() {
                self.hmac_engine.hmac_block(&self.buf, self.is_first())?;
                self.reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(&mut self) -> CaliptraResult<()> {
        if self.state == Hmac384OpState::Final {
            return Err(CaliptraError::DRIVER_HMAC384_INVALID_STATE);
        }

        if self.buf_idx > self.buf.len() {
            return Err(CaliptraError::DRIVER_HMAC384_INVALID_SLICE);
        }

        // Calculate the hmac of the final block
        let buf = &self.buf[..self.buf_idx];
        self.hmac_engine
            .hmac_partial_block(buf, self.is_first(), self.data_size)?;

        // Set the state of the operation to final
        self.state = Hmac384OpState::Final;

        let hmac = self.hmac_engine.hmac.regs();

        // Copy the tag to the specified location
        match &mut self.tag {
            Hmac384Tag::Array4x12(arr) => KvAccess::end_copy_to_arr(hmac.tag(), arr),
            Hmac384Tag::Key(key) => KvAccess::end_copy_to_kv(hmac.kv_wr_status(), *key)
                .map_err(|err| err.into_write_tag_err()),
        }
    }

    /// Check if this the first digest operation
    fn is_first(&self) -> bool {
        self.state == Hmac384OpState::Init
    }

    /// Reset internal buffer state
    fn reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Hmac384OpState::Pending;
    }
}

/// HMAC-384 key access error trait
trait Hmac384KeyAccessErr {
    /// Convert to read key operation error
    fn into_read_key_err(self) -> CaliptraError;

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError;

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> CaliptraError;
}

impl Hmac384KeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC384_READ_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC384_READ_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC384_READ_KEY_KV_UNKNOWN,
        }
    }

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC384_READ_DATA_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC384_READ_DATA_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC384_READ_DATA_KV_UNKNOWN,
        }
    }

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC384_WRITE_TAG_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC384_WRITE_TAG_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC384_WRITE_TAG_KV_UNKNOWN,
        }
    }
}
