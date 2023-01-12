/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384.rs

Abstract:

    File contains API for SHA-384 Cryptography operations

--*/

use core::usize;

use crate::kv_access::{KvAccess, KvAccessErr};
use crate::{
    array::Array4x32, caliptra_err_def, wait, Array4x12, CaliptraResult, KeyReadArgs, KeyWriteArgs,
};
use caliptra_registers::sha512;

const SHA384_BLOCK_BYTE_SIZE: usize = 128;
const SHA384_BLOCK_LEN_OFFSET: usize = 112;
const SHA384_MAX_DATA_SIZE: usize = 1024 * 1024;
const SHA384_MIN_KEY_READ_SIZE: u32 = 1;
const SHA384_MAX_KEY_READ_SIZE: u32 = 16;

caliptra_err_def! {
    Sha384,
    Sha384Err
    {
        // Errors encountered while reading data from key vault
        ReadDataKvRead = 0x01,
        ReadDataKvWrite = 0x02,
        ReadDataKvUnknown = 0x3,

        // Errors encountered while writing digest to key vault
        WriteDigestKvRead = 0x04,
        WriteDigestKvWrite = 0x05,
        WriteDigestKvUnknown = 0x06,

        // Invalid State
        InvalidStateErr = 0x07,

        // Max data limit reached
        MaxDataErr = 0x08,

        // Key Read invalid key size
        InvalidKeySize = 0x09,

        // Invalid slice
        InvalidSlice = 0x0A,

        // Array Index out of bounds
        IndexOutOfBounds = 0x0B,
    }
}

/// SHA-384 Data
pub enum Sha384Data<'a> {
    /// Array
    Slice(&'a [u8]),

    /// Key
    Key(KeyReadArgs),
}

impl<'a> From<&'a [u8]> for Sha384Data<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8]) -> Self {
        Self::Slice(value)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Sha384Data<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a [u8; N]) -> Self {
        Self::Slice(value)
    }
}

impl From<KeyReadArgs> for Sha384Data<'_> {
    /// Converts to this type from the input type.
    fn from(value: KeyReadArgs) -> Self {
        Self::Key(value)
    }
}

/// SHA-384 Digest
pub enum Sha384Digest<'a> {
    /// Array
    Array4x12(&'a mut Array4x12),

    /// Key
    Key(KeyWriteArgs),
}

impl<'a> From<&'a mut Array4x12> for Sha384Digest<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

impl<'a> From<KeyWriteArgs> for Sha384Digest<'a> {
    /// Converts to this type from the input type.
    fn from(value: KeyWriteArgs) -> Self {
        Self::Key(value)
    }
}

#[derive(Default)]
pub struct Sha384 {}

impl Sha384 {
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha384Digest` - Object representing the digest operation
    pub fn digest_init<'a>(
        &'a self,
        mut digest: Sha384Digest<'a>,
    ) -> CaliptraResult<Sha384DigestOp<'a>> {
        let sha = sha512::RegisterBlock::sha512_reg();

        // Configure writing digest to specified destination
        match &mut digest {
            Sha384Digest::Array4x12(arr) => {
                KvAccess::begin_copy_to_arr(sha.kv_wr_status(), sha.kv_wr_ctrl(), arr)?
            }
            Sha384Digest::Key(key) => {
                KvAccess::begin_copy_to_kv(sha.kv_wr_status(), sha.kv_wr_ctrl(), *key)?
            }
        }

        let op = Sha384DigestOp {
            sha: self,
            state: Sha384DigestState::Init,
            buf: [0u8; SHA384_BLOCK_BYTE_SIZE],
            buf_idx: 0,
            data_size: 0,
            digest,
        };

        Ok(op)
    }

    /// Calculate the digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    pub fn digest(&self, data: Sha384Data, mut digest: Sha384Digest) -> CaliptraResult<()> {
        let sha = sha512::RegisterBlock::sha512_reg();

        // Configure writing digest to specified destination
        match &mut digest {
            Sha384Digest::Array4x12(arr) => {
                KvAccess::begin_copy_to_arr(sha.kv_wr_status(), sha.kv_wr_ctrl(), arr)?
            }
            Sha384Digest::Key(key) => {
                KvAccess::begin_copy_to_kv(sha.kv_wr_status(), sha.kv_wr_ctrl(), *key)?
            }
        }

        // Calculate the digest
        match data {
            Sha384Data::Slice(slice) => self.digest_buf(slice)?,
            Sha384Data::Key(key) => self.digest_key(key)?,
        }

        // Copy the digest to specified destination
        match &mut digest {
            Sha384Digest::Array4x12(arr) => KvAccess::end_copy_to_arr(sha.digest(), *arr),
            Sha384Digest::Key(key) => KvAccess::end_copy_to_kv(sha.kv_wr_status(), *key)
                .map_err(|err| err.into_write_digest_err().into()),
        }
    }

    /// Calculate the digest of the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the digest over
    fn digest_buf(&self, buf: &[u8]) -> CaliptraResult<()> {
        // Check if the buffer is not large
        if buf.len() > SHA384_MAX_DATA_SIZE {
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
                        self.digest_partial_block(slice, first, buf.len())?;
                        break;
                    } else {
                        raise_err!(InvalidSlice)
                    }
                }
                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic call.
                    if let Some(slice) = buf.get(offset..offset + SHA384_BLOCK_BYTE_SIZE) {
                        let block = <&[u8; SHA384_BLOCK_BYTE_SIZE]>::try_from(slice).unwrap();
                        self.digest_block(block, first)?;
                        bytes_remaining -= SHA384_BLOCK_BYTE_SIZE;
                        first = false;
                    } else {
                        raise_err!(InvalidSlice)
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate digest of a key in the Key Vault
    ///
    /// # Arguments
    ///
    /// * `key` - Key to calculate digest for
    fn digest_key(&self, key: KeyReadArgs) -> CaliptraResult<()> {
        if !(SHA384_MIN_KEY_READ_SIZE..SHA384_MAX_KEY_READ_SIZE + 1).contains(&key.word_size) {
            raise_err!(InvalidKeySize)
        }

        let sha = sha512::RegisterBlock::sha512_reg();

        KvAccess::copy_from_kv(key, sha.kv_rd_status(), sha.kv_rd_ctrl())
            .map_err(|err| err.into_read_data_err())?;

        self.digest_op(true)
    }

    /// Calculate the digest of the last block
    ///
    /// # Arguments
    ///
    /// * `slice` - Slice of buffer to digest
    /// * `first` - Flag indicating if this is the first buffer
    /// * `buf_size` - Total buffer size
    fn digest_partial_block(
        &self,
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

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            raise_err!(IndexOutOfBounds)
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA384_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.digest_block(&block, first)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA384_BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            self.digest_block(&block, false)?;
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
        &self,
        block: &[u8; SHA384_BLOCK_BYTE_SIZE],
        first: bool,
    ) -> CaliptraResult<()> {
        let sha512 = sha512::RegisterBlock::sha512_reg();
        Array4x32::from(block).write_to_reg(sha512.block());
        self.digest_op(first)
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first` - Flag indicating if this is the first block
    fn digest_op(&self, first: bool) -> CaliptraResult<()> {
        const MODE_SHA384: u32 = 0b10;

        let sha = sha512::RegisterBlock::sha512_reg();

        // Wait for the hardware to be ready
        wait::until(|| sha.status().read().ready());

        if first {
            // Submit the first block
            sha.ctrl()
                .write(|w| w.mode(MODE_SHA384).init(true).next(false));
        } else {
            // Submit next block in existing hashing chain
            sha.ctrl()
                .write(|w| w.mode(MODE_SHA384).init(false).next(true));
        }

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
    sha: &'a Sha384,

    /// State
    state: Sha384DigestState,

    /// Staging buffer
    buf: [u8; SHA384_BLOCK_BYTE_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,

    /// Digest
    digest: Sha384Digest<'a>,
}

impl<'a> Sha384DigestOp<'a> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state == Sha384DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > SHA384_MAX_DATA_SIZE {
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
                self.sha.digest_block(&self.buf, self.is_first())?;
                self.reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    pub fn finalize(&mut self) -> CaliptraResult<()> {
        if self.state == Sha384DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.buf_idx > self.buf.len() {
            raise_err!(InvalidSlice)
        }

        // Calculate the digest of the final block
        let buf = &self.buf[..self.buf_idx];
        self.sha
            .digest_partial_block(buf, self.is_first(), self.data_size)?;

        // Set the state of the operation to final
        self.state = Sha384DigestState::Final;

        let sha = sha512::RegisterBlock::sha512_reg();

        // Copy the digest to specified destination
        match &mut self.digest {
            Sha384Digest::Array4x12(arr) => KvAccess::end_copy_to_arr(sha.digest(), *arr),
            Sha384Digest::Key(key) => KvAccess::end_copy_to_kv(sha.kv_wr_status(), *key)
                .map_err(|err| err.into_write_digest_err().into()),
        }
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
    fn into_read_data_err(self) -> Sha384Err;

    /// Convert to write digest operation error
    fn into_write_digest_err(self) -> Sha384Err;
}

impl Sha384KeyAccessErr for KvAccessErr {
    /// Convert to read data operation error
    fn into_read_data_err(self) -> Sha384Err {
        match self {
            KvAccessErr::KeyRead => Sha384Err::ReadDataKvRead,
            KvAccessErr::KeyWrite => Sha384Err::ReadDataKvWrite,
            KvAccessErr::Generic => Sha384Err::ReadDataKvUnknown,
        }
    }

    /// Convert to write digest operation error
    fn into_write_digest_err(self) -> Sha384Err {
        match self {
            KvAccessErr::KeyRead => Sha384Err::WriteDigestKvRead,
            KvAccessErr::KeyWrite => Sha384Err::WriteDigestKvWrite,
            KvAccessErr::Generic => Sha384Err::WriteDigestKvUnknown,
        }
    }
}
