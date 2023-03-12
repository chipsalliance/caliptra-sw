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
use crate::{array::Array4x32, caliptra_err_def, wait, Array4x12, CaliptraResult};
use caliptra_registers::sha512;

const SHA384_BLOCK_BYTE_SIZE: usize = 128;
const SHA384_BLOCK_LEN_OFFSET: usize = 112;
const SHA384_MAX_DATA_SIZE: usize = 1024 * 1024;
const SHA384_HASH_SIZE: usize = 48;

caliptra_err_def! {
    Sha384,
    Sha384Err
    {
        // Errors encountered while reading data from key vault
        ReadDataKvRead = 0x01,
        ReadDataKvWrite = 0x02,
        ReadDataKvUnknown = 0x3,

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
#[derive(Debug, Copy, Clone)]
pub enum Sha384Data<'a> {
    /// Array
    Slice(&'a [u8]),

    /// PCR hash extend arguments
    PcrHashExtend(PcrHashExtendArgs<'a>),
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

impl<'a> From<PcrHashExtendArgs<'a>> for Sha384Data<'a> {
    /// Converts to this type from the input type.
    fn from(value: PcrHashExtendArgs<'a>) -> Self {
        Self::PcrHashExtend(value)
    }
}

/// Key read operation arguments
#[derive(Debug, Clone, Copy)]
pub struct PcrHashExtendArgs<'a> {
    /// Array
    pub slice: &'a [u8],

    /// PCR hash extend
    pub hash_extend: bool,

    /// Pcr Id
    pub id: PcrId,
}

impl<'a> PcrHashExtendArgs<'a> {
    /// Create an instance of `KeyReadArgs`
    ///
    /// # Arguments
    ///
    /// * `id` - Key Id
    pub fn new(slice: &'a [u8], hash_extend: bool, id: PcrId) -> Self {
        Self {
            slice,
            hash_extend,
            id,
        }
    }
}

/// SHA-384 Digest
#[derive(Debug)]
pub enum Sha384Digest<'a> {
    /// Array
    Array4x12(&'a mut Array4x12),
}

impl<'a> From<&'a mut Array4x12> for Sha384Digest<'a> {
    /// Converts to this type from the input type.
    fn from(value: &'a mut Array4x12) -> Self {
        Self::Array4x12(value)
    }
}

#[derive(Default, Debug)]
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
        }

        match data {
            Sha384Data::Slice(slice) => {
                // Calculate the digest
                self.digest_buf(slice, 0)?;
            }
            Sha384Data::PcrHashExtend(hash_extend) => {
                self.retrieve_pcr(hash_extend.id)?;

                // Calculate the digest
                self.digest_buf(hash_extend.slice, SHA384_HASH_SIZE)?;
            }
        }

        // Copy the digest to specified destination
        match &mut digest {
            Sha384Digest::Array4x12(arr) => {
                KvAccess::end_copy_to_arr(sha.digest().truncate::<12>(), *arr)
            }
        }
    }

    /// Calculate the digest of the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the digest over
    /// * `pcr_hash_extend` - Indicates if pcr is to be hash extended.
    fn digest_buf(&self, buf: &[u8], prepad_byte_count_in: usize) -> CaliptraResult<()> {
        let mut prepad_byte_count = prepad_byte_count_in;
        let total_bytes = prepad_byte_count_in + buf.len();

        // Check if the buffer is not large
        if total_bytes > SHA384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        let mut first = true;
        let mut bytes_remaining = total_bytes;
        let mut block = [0u8; SHA384_BLOCK_BYTE_SIZE];

        loop {
            let offset = (buf.len() + prepad_byte_count) - bytes_remaining;
            match bytes_remaining {
                0..=127 => {
                    // PANIC-FREE: Use buf.get() instead of buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic.
                    if let Some(slice) = buf.get(offset..) {
                        // If this is the first block, create a block with the prepad.
                        if first && prepad_byte_count > 0 {
                            // PANIC-FREE: Following check optimizes the out of bounds
                            // panic in copy_from_slice below.
                            if prepad_byte_count > bytes_remaining {
                                raise_err!(IndexOutOfBounds)
                            }

                            block[prepad_byte_count..bytes_remaining].copy_from_slice(slice);
                            if let Some(extended_slice) = block.get(..bytes_remaining) {
                                self.digest_partial_block(extended_slice, first, total_bytes)?;
                            } else {
                                raise_err!(InvalidSlice)
                            }
                        } else {
                            self.digest_partial_block(slice, first, total_bytes)?;
                        }
                        break;
                    } else {
                        raise_err!(InvalidSlice)
                    }
                }
                _ => {
                    // PANIC-FREE: Use buf.get() instead if buf[] as the compiler
                    // cannot reason about `offset` parameter to optimize out
                    // the panic call.
                    if let Some(mut slice) =
                        buf.get(offset..offset + (SHA384_BLOCK_BYTE_SIZE - prepad_byte_count))
                    {
                        // If this is the first block, create a block with the prepad.
                        if first && prepad_byte_count > 0 {
                            if prepad_byte_count > (block.len() - 1) {
                                raise_err!(IndexOutOfBounds)
                            }
                            block[prepad_byte_count..].copy_from_slice(slice); // [TODO] fix this panic: slice_start_index_len_fail
                            slice = &block;
                            prepad_byte_count = 0;
                        }

                        // PANIC-FREE: Following check optimizes the out of bounds
                        // panic in unwrap below.
                        if slice.len() != SHA384_BLOCK_BYTE_SIZE {
                            raise_err!(InvalidSlice)
                        }
                        let block = <&[u8; SHA384_BLOCK_BYTE_SIZE]>::try_from(slice).unwrap();
                        self.digest_block(block, first, false)?;
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

    /// Waits for the PCR to be retrieved from the PCR vault
    /// and copied to the block registers.
    ///
    /// # Arguments
    ///
    /// * `pcr_id` - PCR to hash extend
    fn retrieve_pcr(&self, pcr_id: PcrId) -> CaliptraResult<()> {
        let sha = sha512::RegisterBlock::sha512_reg();

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
        let mut last = false;

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            raise_err!(IndexOutOfBounds)
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
        &self,
        block: &[u8; SHA384_BLOCK_BYTE_SIZE],
        first: bool,
        last: bool,
    ) -> CaliptraResult<()> {
        let sha512 = sha512::RegisterBlock::sha512_reg();
        Array4x32::from(block).write_to_reg(sha512.block());
        self.digest_op(first, last)
    }

    // Perform the digest operation in the hardware
    //
    // # Arguments
    //
    /// * `first` - Flag indicating if this is the first block
    /// * `last` - Flag indicating if this is the last block
    fn digest_op(&self, first: bool, last: bool) -> CaliptraResult<()> {
        const MODE_SHA384: u32 = 0b10;

        let sha = sha512::RegisterBlock::sha512_reg();

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
                self.sha.digest_block(&self.buf, self.is_first(), false)?;
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
            Sha384Digest::Array4x12(arr) => {
                KvAccess::end_copy_to_arr(sha.digest().truncate::<12>(), *arr)
            }
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
}
