/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac.rs

Abstract:

    File contains API for HMAC-384 and HMAC-512 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array::Array4x32, wait, Array4x12, Array4x16, CaliptraError, CaliptraResult, KeyReadArgs,
    KeyWriteArgs, Trng,
};

#[cfg(not(feature = "no-cfi"))]
use caliptra_cfi_derive::cfi_impl_fn;
use caliptra_registers::hmac::HmacReg;
use core::usize;

const HMAC_BLOCK_SIZE_BYTES: usize = 128;
const HMAC_BLOCK_LEN_OFFSET: usize = 112;
const HMAC_MAX_DATA_SIZE: usize = 1024 * 1024;

/// HMAC Data
#[derive(Debug, Copy, Clone)]
pub enum HmacData<'a> {
    /// Slice
    Slice(&'a [u8]),

    /// Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a [u8]> for HmacData<'a> {
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for HmacData<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8; N]) -> Self {
        Self::Slice(value)
    }
}

impl From<KeyReadArgs> for HmacData<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// Hmac Tag
#[derive(Debug)]
pub enum HmacTag<'a> {
    /// Array - 48 Bytes
    Array4x12(&'a mut Array4x12),

    /// Array - 64 Bytes
    Array4x16(&'a mut Array4x16),

    /// Key output
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for HmacTag<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<&'a mut Array4x16> for HmacTag<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x16) -> Self {
        Self::Array4x16(value)
    }
}

impl<'a> From<KeyWriteArgs> for HmacTag<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

///
/// Hmac Key
///
#[derive(Debug, Copy, Clone)]
pub enum HmacKey<'a> {
    /// Array - 48 Bytes
    Array4x12(&'a Array4x12),

    /// Array - 64 Bytes
    Array4x16(&'a Array4x16),

    // Key
    Key(KeyReadArgs),

    // CSR mode key
    CsrMode(),
}

impl<'a> From<&'a Array4x12> for HmacKey<'a> {
    ///
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<&'a Array4x16> for HmacKey<'a> {
    ///
    /// Converts to this type from the input type.
    ///
    fn from(value: &'a Array4x16) -> Self {
        Self::Array4x16(value)
    }
}

impl From<KeyReadArgs> for HmacKey<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HmacMode {
    Hmac384 = 0,
    Hmac512 = 1,
}

struct HmacParams<'a> {
    slice: &'a [u8],
    first: bool,
    buf_size: usize,
    key: Option<KeyReadArgs>,
    dest_key: Option<KeyWriteArgs>,
    hmac_mode: HmacMode,
    csr_mode: bool,
}

pub struct Hmac {
    hmac: HmacReg,
}

impl Hmac {
    pub fn new(hmac: HmacReg) -> Self {
        Self { hmac }
    }
    /// Initialize multi step HMAC operation
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `trng` - TRNG driver instance
    /// * `tag`  -  The calculated tag
    /// * `hmac_mode` - Hmac mode to use
    ///
    /// # Returns
    /// * `HmacOp` - Hmac operation
    pub fn hmac_init<'a>(
        &'a mut self,
        key: &HmacKey,
        trng: &mut Trng,
        mut tag: HmacTag<'a>,
        hmac_mode: HmacMode,
    ) -> CaliptraResult<HmacOp> {
        let hmac = self.hmac.regs_mut();
        let mut csr_mode = false;

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        if matches!(&mut tag, HmacTag::Array4x12(_) | HmacTag::Array4x16(_)) {
            KvAccess::begin_copy_to_arr(hmac.hmac512_kv_wr_status(), hmac.hmac512_kv_wr_ctrl())?;
        }

        // Configure the hardware to use key to use for the HMAC operation
        let key = match key {
            HmacKey::Array4x12(arr) => {
                KvAccess::copy_from_arr(arr, hmac.hmac512_key().truncate::<12>())?;
                None
            }
            HmacKey::Array4x16(arr) => {
                KvAccess::copy_from_arr(arr, hmac.hmac512_key())?;
                None
            }
            HmacKey::Key(key) => Some(*key),
            HmacKey::CsrMode() => {
                csr_mode = true;
                None
            }
        };

        // Generate an LFSR seed and copy to key vault.
        self.gen_lfsr_seed(trng)?;

        let op = HmacOp {
            hmac_engine: self,
            key,
            state: HmacOpState::Init,
            buf: [0u8; HMAC_BLOCK_SIZE_BYTES],
            buf_idx: 0,
            data_size: 0,
            tag,
            hmac_mode,
            csr_mode,
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
        let iv: [u32; 12] = rand_data.0[..12].try_into().unwrap();
        KvAccess::copy_from_arr(&Array4x12::from(iv), hmac.hmac512_lfsr_seed())?;
        Ok(())
    }

    /// Calculate the hmac for specified data
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    /// * `data` - Data to calculate the HMAC over
    /// * `trng` - TRNG driver instance
    /// * `tag`  -  The calculated tag
    /// * `hmac_mode` - Hmac mode to use
    ///
    /// # Returns
    /// * `CaliptraResult<()>` - Result of the operation
    #[cfg_attr(not(feature = "no-cfi"), cfi_impl_fn)]
    pub fn hmac(
        &mut self,
        key: &HmacKey,
        data: &HmacData,
        trng: &mut Trng,
        tag: HmacTag,
        hmac_mode: HmacMode,
    ) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();
        let mut tag = tag;
        let mut csr_mode: bool = false;

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        let dest_key = match &mut tag {
            HmacTag::Array4x12(_) | HmacTag::Array4x16(_) => {
                KvAccess::begin_copy_to_arr(
                    hmac.hmac512_kv_wr_status(),
                    hmac.hmac512_kv_wr_ctrl(),
                )?;
                None
            }
            HmacTag::Key(dest_key) => Some(*dest_key),
        };

        // Configure the hardware to use key to use for the HMAC operation
        let key = match *key {
            HmacKey::Array4x12(arr) => {
                KvAccess::copy_from_arr(arr, hmac.hmac512_key().truncate::<12>())?;
                None
            }
            HmacKey::Array4x16(arr) => {
                KvAccess::copy_from_arr(arr, hmac.hmac512_key())?;
                None
            }
            HmacKey::Key(key) => Some(key),
            HmacKey::CsrMode() => {
                csr_mode = true;
                None
            }
        };
        // Generate an LFSR seed and copy to key vault.
        self.gen_lfsr_seed(trng)?;

        // Calculate the hmac
        match data {
            HmacData::Slice(buf) => self.hmac_buf(buf, key, dest_key, hmac_mode, csr_mode)?,
            HmacData::Key(data_key) => self.hmac_key(*data_key, key, dest_key, hmac_mode)?,
        }
        let hmac = self.hmac.regs();

        // Copy the tag to the specified location
        let result = match &mut tag {
            HmacTag::Array4x12(arr) => {
                KvAccess::end_copy_to_arr(hmac.hmac512_tag().truncate::<12>(), arr)
            }
            HmacTag::Array4x16(arr) => KvAccess::end_copy_to_arr(hmac.hmac512_tag(), arr),
            _ => Ok(()),
        };

        self.zeroize_internal();

        result
    }

    /// Zeroize the hardware registers.
    fn zeroize_internal(&mut self) {
        self.hmac
            .regs_mut()
            .hmac512_ctrl()
            .write(|w| w.zeroize(true).mode(false).csr_mode(false));
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
        hmac.regs_mut()
            .hmac512_ctrl()
            .write(|w| w.zeroize(true).mode(false).csr_mode(false));
    }

    ///
    /// Calculate the hmac of the buffer provided as parameter
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the hmac over
    /// * `key` - Key to use for the hmac operation
    /// * `dest_key` - Destination key to store the hmac tag
    /// * `hmac_mode` - Hmac mode to use
    /// * `csr_mode` - Flag indicating if the hmac operation is in CSR mode
    ///
    /// # Returns
    /// * `CaliptraResult<()>` - Result of the operation
    fn hmac_buf(
        &mut self,
        buf: &[u8],
        key: Option<KeyReadArgs>,
        dest_key: Option<KeyWriteArgs>,
        hmac_mode: HmacMode,
        csr_mode: bool,
    ) -> CaliptraResult<()> {
        // Check if the buffer is within the size that we support
        if buf.len() > HMAC_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_HMAC_MAX_DATA);
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
                        let params = HmacParams {
                            slice,
                            first,
                            buf_size: buf.len(),
                            key,
                            dest_key,
                            hmac_mode,
                            csr_mode,
                        };
                        self.hmac_partial_block(params)?;
                        break;
                    } else {
                        return Err(CaliptraError::DRIVER_HMAC_INVALID_SLICE);
                    }
                }

                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic.
                    if let Some(slice) = buf.get(offset..offset + HMAC_BLOCK_SIZE_BYTES) {
                        let block = <&[u8; HMAC_BLOCK_SIZE_BYTES]>::try_from(slice).unwrap();
                        self.hmac_block(block, first, key, dest_key, hmac_mode, csr_mode)?;
                        bytes_remaining -= HMAC_BLOCK_SIZE_BYTES;
                        first = false;
                    } else {
                        return Err(CaliptraError::DRIVER_HMAC_INVALID_SLICE);
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
    fn hmac_key(
        &mut self,
        data_key: KeyReadArgs,
        key: Option<KeyReadArgs>,
        dest_key: Option<KeyWriteArgs>,
        hmac_mode: HmacMode,
    ) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        KvAccess::copy_from_kv(
            data_key,
            hmac.hmac512_kv_rd_block_status(),
            hmac.hmac512_kv_rd_block_ctrl(),
        )
        .map_err(|err| err.into_read_data_err())?;

        self.hmac_op(true, key, dest_key, hmac_mode, false)
    }

    fn hmac_partial_block(&mut self, params: HmacParams) -> CaliptraResult<()> {
        /// Set block length
        fn set_block_len(buf_size: usize, block: &mut [u8; HMAC_BLOCK_SIZE_BYTES]) {
            let bit_len = ((buf_size + HMAC_BLOCK_SIZE_BYTES) as u128) << 3;
            block[HMAC_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; HMAC_BLOCK_SIZE_BYTES];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if params.slice.len() > block.len() - 1 {
            return Err(CaliptraError::DRIVER_HMAC_INDEX_OUT_OF_BOUNDS);
        }
        block[..params.slice.len()].copy_from_slice(params.slice);
        block[params.slice.len()] = 0b1000_0000;
        if params.slice.len() < HMAC_BLOCK_LEN_OFFSET {
            set_block_len(params.buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.hmac_block(
            &block,
            params.first,
            params.key,
            params.dest_key,
            params.hmac_mode,
            params.csr_mode,
        )?;

        // Add a padding block if one is needed
        if params.slice.len() >= HMAC_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(params.buf_size, &mut block);
            self.hmac_block(
                &block,
                false,
                params.key,
                params.dest_key,
                params.hmac_mode,
                params.csr_mode,
            )?;
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
    /// * `key` - Key vault slot to use for the hmac key
    /// * `dest_key` - Destination key vault slot to store the hmac tag
    /// * `hmac_mode` - Hmac mode to use
    /// * `csr_mode` - Flag indicating if the hmac operation is in CSR mode
    ///
    /// # Returns
    /// * `CaliptraResult<()>` - Result of the operation
    fn hmac_block(
        &mut self,
        block: &[u8; HMAC_BLOCK_SIZE_BYTES],
        first: bool,
        key: Option<KeyReadArgs>,
        dest_key: Option<KeyWriteArgs>,
        hmac_mode: HmacMode,
        csr_mode: bool,
    ) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();
        Array4x32::from(block).write_to_reg(hmac.hmac512_block());
        self.hmac_op(first, key, dest_key, hmac_mode, csr_mode)
    }

    ///
    /// Perform the hmac operation in the hardware
    ///
    /// # Arguments
    ///
    /// * `first` - Flag indicating if this is the first block
    /// * `key` - Key vault slot to use for the hmac key
    /// * `dest_key` - Destination key vault slot to store the hmac tag
    /// * `hmac_mode` - Hmac mode to use
    /// * `csr_mode` - Flag indicating if the hmac operation is in CSR mode
    ///
    /// # Returns
    /// * `CaliptraResult<()>` - Result of the operation
    fn hmac_op(
        &mut self,
        first: bool,
        key: Option<KeyReadArgs>,
        dest_key: Option<KeyWriteArgs>,
        hmac_mode: HmacMode,
        csr_mode: bool,
    ) -> CaliptraResult<()> {
        let hmac = self.hmac.regs_mut();

        if let Some(key) = key {
            KvAccess::copy_from_kv(
                key,
                hmac.hmac512_kv_rd_key_status(),
                hmac.hmac512_kv_rd_key_ctrl(),
            )
            .map_err(|err| err.into_read_key_err())?
        };
        if let Some(dest_key) = dest_key {
            KvAccess::begin_copy_to_kv(
                hmac.hmac512_kv_wr_status(),
                hmac.hmac512_kv_wr_ctrl(),
                dest_key,
            )?;
        }

        // Wait for the hardware to be ready
        wait::until(|| hmac.hmac512_status().read().ready());

        if first {
            // Submit the first block
            hmac.hmac512_ctrl().write(|w| {
                w.init(true)
                    .next(false)
                    .mode(hmac_mode == HmacMode::Hmac512)
                    .csr_mode(csr_mode)
            });
        } else {
            // Submit next block in existing hashing chain
            hmac.hmac512_ctrl().write(|w| {
                w.init(false)
                    .next(true)
                    .mode(hmac_mode == HmacMode::Hmac512)
                    .csr_mode(csr_mode)
            });
        }

        // Wait for the hmac operation to finish
        wait::until(|| hmac.hmac512_status().read().valid());

        if let Some(dest_key) = dest_key {
            KvAccess::end_copy_to_kv(hmac.hmac512_kv_wr_status(), dest_key)
                .map_err(|err| err.into_write_tag_err())?;
        }

        Ok(())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum HmacOpState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// HMAC multi step operation
pub struct HmacOp<'a> {
    /// Hmac Engine
    hmac_engine: &'a mut Hmac,

    /// State
    state: HmacOpState,

    // The keyvault key used to compute the hmac
    key: Option<KeyReadArgs>,

    /// Staging buffer
    buf: [u8; HMAC_BLOCK_SIZE_BYTES],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,

    /// Tag
    tag: HmacTag<'a>,

    /// Hmac Mode
    hmac_mode: HmacMode,

    /// CSR mode
    csr_mode: bool,
}

impl<'a> HmacOp<'a> {
    ///
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state == HmacOpState::Final {
            return Err(CaliptraError::DRIVER_HMAC_INVALID_STATE);
        }

        if self.data_size + data.len() > HMAC_MAX_DATA_SIZE {
            return Err(CaliptraError::DRIVER_HMAC_MAX_DATA);
        }

        for byte in data {
            self.data_size += 1;

            // PANIC-FREE: Following check optimizes the out of bounds
            // panic in indexing the `buf`
            if self.buf_idx >= self.buf.len() {
                return Err(CaliptraError::DRIVER_HMAC_INDEX_OUT_OF_BOUNDS);
            }

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the digest of accumulated data
            if self.buf_idx == self.buf.len() {
                self.hmac_engine.hmac_block(
                    &self.buf,
                    self.is_first(),
                    self.key,
                    self.dest_key(),
                    self.hmac_mode,
                    self.csr_mode,
                )?;
                self.reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(&mut self) -> CaliptraResult<()> {
        if self.state == HmacOpState::Final {
            return Err(CaliptraError::DRIVER_HMAC_INVALID_STATE);
        }

        if self.buf_idx > self.buf.len() {
            return Err(CaliptraError::DRIVER_HMAC_INVALID_SLICE);
        }

        // Calculate the hmac of the final block
        let buf = &self.buf[..self.buf_idx];

        #[cfg(feature = "fips-test-hooks")]
        let buf = unsafe {
            crate::FipsTestHook::corrupt_data_if_hook_set(
                crate::FipsTestHook::HMAC384_CORRUPT_TAG,
                &buf,
            )
        };

        let params = HmacParams {
            slice: buf,
            first: self.is_first(),
            buf_size: self.data_size,
            key: self.key,
            dest_key: self.dest_key(),
            hmac_mode: self.hmac_mode,
            csr_mode: self.csr_mode,
        };

        self.hmac_engine.hmac_partial_block(params)?;

        // Set the state of the operation to final
        self.state = HmacOpState::Final;

        let hmac = self.hmac_engine.hmac.regs();

        // Copy the tag to the specified location
        match &mut self.tag {
            HmacTag::Array4x12(arr) => {
                KvAccess::end_copy_to_arr(hmac.hmac512_tag().truncate::<12>(), arr)
            }
            HmacTag::Array4x16(arr) => KvAccess::end_copy_to_arr(hmac.hmac512_tag(), arr),
            HmacTag::Key(key) => KvAccess::end_copy_to_kv(hmac.hmac512_kv_wr_status(), *key)
                .map_err(|err| err.into_write_tag_err()),
        }
    }
    fn dest_key(&self) -> Option<KeyWriteArgs> {
        match self.tag {
            HmacTag::Key(key) => Some(key),
            _ => None,
        }
    }

    /// Check if this the first digest operation
    fn is_first(&self) -> bool {
        self.state == HmacOpState::Init
    }

    /// Reset internal buffer state
    fn reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = HmacOpState::Pending;
    }
}

/// HMAC key access error trait
trait HmacKeyAccessErr {
    /// Convert to read key operation error
    fn into_read_key_err(self) -> CaliptraError;

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError;

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> CaliptraError;
}

impl HmacKeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_key_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC_READ_KEY_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC_READ_KEY_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC_READ_KEY_KV_UNKNOWN,
        }
    }

    /// Convert to read data operation error
    fn into_read_data_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC_READ_DATA_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC_READ_DATA_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC_READ_DATA_KV_UNKNOWN,
        }
    }

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> CaliptraError {
        match self {
            KvAccessErr::KeyRead => CaliptraError::DRIVER_HMAC_WRITE_TAG_KV_READ,
            KvAccessErr::KeyWrite => CaliptraError::DRIVER_HMAC_WRITE_TAG_KV_WRITE,
            KvAccessErr::Generic => CaliptraError::DRIVER_HMAC_WRITE_TAG_KV_UNKNOWN,
        }
    }
}
