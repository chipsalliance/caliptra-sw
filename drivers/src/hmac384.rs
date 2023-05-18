/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384.rs

Abstract:

    File contains API for HMAC-384 Cryptography operations

--*/

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array::Array4x32, caliptra_err_def, wait, Array4x12, CaliptraResult, KeyReadArgs, KeyWriteArgs,
};
use caliptra_registers::hmac;
use core::usize;

const HMAC384_BLOCK_SIZE_BYTES: usize = 128;
const HMAC384_BLOCK_LEN_OFFSET: usize = 112;
const HMAC384_MAX_DATA_SIZE: usize = 1024 * 1024;

caliptra_err_def! {
    Hmac384,
    Hmac384Err
    {
        // Errors encountered while reading the key from key vault
        ReadKeyKvRead = 0x01,
        ReadKeyKvWrite = 0x02,
        ReadKeyKvUnknown = 0x03,

        // Errors encountered while reading the data from key vault
        ReadDataKvRead = 0x04,
        ReadDataKvWrite = 0x05,
        ReadDataKvUnknown = 0x06,

        // Errors encountered while writing Tag to key vault
        WriteTagKvRead = 0x07,
        WriteTagKvWrite = 0x08,
        WriteTagKvUnknown = 0x09,

        // Key Read invalid key size
        InvalidKeySize = 0x0A,

        // Invalid state
        InvalidStateErr = 0x0B,

        // Max data limit reached
        MaxDataErr =  0x0C,

        // Invalid slice
        InvalidSlice = 0x0D,

        // Array Index out of bounds
        IndexOutOfBounds = 0x0E,
    }
}

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

#[derive(Default, Debug)]
pub struct Hmac384 {}

impl Hmac384 {
    /// Initialize multi step HMAC operation
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    ///
    /// * `tag`  -  The calculated tag
    pub fn hmac_init<'a>(
        &'a mut self,
        key: Hmac384Key,
        mut tag: Hmac384Tag<'a>,
    ) -> CaliptraResult<Hmac384Op> {
        let hmac = hmac::RegisterBlock::hmac_reg();

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        match &mut tag {
            Hmac384Tag::Array4x12(arr) => {
                KvAccess::begin_copy_to_arr(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), arr)?
            }
            Hmac384Tag::Key(key) => {
                KvAccess::begin_copy_to_kv(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), *key)?
            }
        }

        // Configure the hardware to use key to use for the HMAC operation
        match key {
            Hmac384Key::Array4x12(arr) => KvAccess::copy_from_arr(arr, hmac.key())?,
            Hmac384Key::Key(key) => {
                KvAccess::copy_from_kv(key, hmac.kv_rd_key_status(), hmac.kv_rd_key_ctrl())
                    .map_err(|err| err.into_read_key_err())?
            }
        }

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

    /// Calculate the hmac for specified data
    ///
    /// # Arguments
    ///
    /// * `key`  - HMAC Key
    ///
    /// * `data` - Data to calculate the HMAC over
    ///
    /// * `tag`  -  The calculated tag
    pub fn hmac(
        &mut self,
        key: Hmac384Key,
        data: Hmac384Data,
        mut tag: Hmac384Tag,
    ) -> CaliptraResult<()> {
        let hmac = hmac::RegisterBlock::hmac_reg();

        // Configure the hardware so that the output tag is stored at a location specified by the
        // caller.
        match &mut tag {
            Hmac384Tag::Array4x12(arr) => {
                KvAccess::begin_copy_to_arr(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), arr)?
            }
            Hmac384Tag::Key(key) => {
                KvAccess::begin_copy_to_kv(hmac.kv_wr_status(), hmac.kv_wr_ctrl(), *key)?
            }
        }

        // Configure the hardware to use key to use for the HMAC operation
        match key {
            Hmac384Key::Array4x12(arr) => KvAccess::copy_from_arr(arr, hmac.key())?,
            Hmac384Key::Key(key) => {
                KvAccess::copy_from_kv(key, hmac.kv_rd_key_status(), hmac.kv_rd_key_ctrl())
                    .map_err(|err| err.into_read_key_err())?
            }
        }

        // Calculate the hmac
        match data {
            Hmac384Data::Slice(buf) => self.hmac_buf(buf)?,
            Hmac384Data::Key(key) => self.hmac_key(key)?,
        }

        // Copy the tag to the specified location
        match &mut tag {
            Hmac384Tag::Array4x12(arr) => KvAccess::end_copy_to_arr(hmac.tag(), arr),
            Hmac384Tag::Key(key) => KvAccess::end_copy_to_kv(hmac.kv_wr_status(), *key)
                .map_err(|err| err.into_write_tag_err().into()),
        }
    }

    ///
    /// Calculate the hmac of the buffer provided as partoameter
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the hmac over
    ///
    fn hmac_buf(&mut self, buf: &[u8]) -> CaliptraResult<()> {
        // Check if the buffer is within the size that we support
        if buf.len() > HMAC384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
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
                        raise_err!(InvalidSlice)
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
                        raise_err!(InvalidSlice)
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
        let hmac = hmac::RegisterBlock::hmac_reg();

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
            raise_err!(IndexOutOfBounds)
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
        let hmac384 = hmac::RegisterBlock::hmac_reg();
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
        let hmac = hmac::RegisterBlock::hmac_reg();

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
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > HMAC384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        for byte in data {
            self.data_size += 1;

            // PANIC-FREE: Following check optimizes the out of bounds
            // panic in indexing the `buf`
            if self.buf_idx >= self.buf.len() {
                raise_err!(IndexOutOfBounds)
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
            raise_err!(InvalidStateErr)
        }

        if self.buf_idx > self.buf.len() {
            raise_err!(InvalidSlice)
        }

        // Calculate the hmac of the final block
        let buf = &self.buf[..self.buf_idx];
        self.hmac_engine
            .hmac_partial_block(buf, self.is_first(), self.data_size)?;

        // Set the state of the operation to final
        self.state = Hmac384OpState::Final;

        let hmac = hmac::RegisterBlock::hmac_reg();

        // Copy the tag to the specified location
        match &mut self.tag {
            Hmac384Tag::Array4x12(arr) => KvAccess::end_copy_to_arr(hmac.tag(), arr),
            Hmac384Tag::Key(key) => KvAccess::end_copy_to_kv(hmac.kv_wr_status(), *key)
                .map_err(|err| err.into_write_tag_err().into()),
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
    fn into_read_key_err(self) -> Hmac384Err;

    /// Convert to read data operation error
    fn into_read_data_err(self) -> Hmac384Err;

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> Hmac384Err;
}

impl Hmac384KeyAccessErr for KvAccessErr {
    /// Convert to read seed operation error
    fn into_read_key_err(self) -> Hmac384Err {
        match self {
            KvAccessErr::KeyRead => Hmac384Err::ReadKeyKvRead,
            KvAccessErr::KeyWrite => Hmac384Err::ReadKeyKvWrite,
            KvAccessErr::Generic => Hmac384Err::ReadKeyKvUnknown,
        }
    }

    /// Convert to read data operation error
    fn into_read_data_err(self) -> Hmac384Err {
        match self {
            KvAccessErr::KeyRead => Hmac384Err::ReadDataKvRead,
            KvAccessErr::KeyWrite => Hmac384Err::ReadDataKvWrite,
            KvAccessErr::Generic => Hmac384Err::ReadDataKvUnknown,
        }
    }

    /// Convert to write tag operation error
    fn into_write_tag_err(self) -> Hmac384Err {
        match self {
            KvAccessErr::KeyRead => Hmac384Err::WriteTagKvRead,
            KvAccessErr::KeyWrite => Hmac384Err::WriteTagKvWrite,
            KvAccessErr::Generic => Hmac384Err::WriteTagKvUnknown,
        }
    }
}
