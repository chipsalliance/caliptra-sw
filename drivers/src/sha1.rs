/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1.rs

Abstract:

    File contains API for SHA1 Cryptography operations

--*/

use crate::{caliptra_err_def, Array4x5, CaliptraResult};

const SHA1_BLOCK_BYTE_SIZE: usize = 64;
const SHA1_BLOCK_LEN_OFFSET: usize = 56;
const SHA1_MAX_DATA_SIZE: usize = 1024 * 1024;

pub type Sha1Digest<'a> = &'a mut Array4x5;

caliptra_err_def! {
    Sha1,
    Sha1Err
    {
        // Invalid State
        InvalidStateErr = 0x01,

        // Max data limit reached
        MaxDataErr = 0x02,

        // Invalid slice
        InvalidSlice = 0x03,

        // Array Index out of bounds
        IndexOutOfBounds = 0x04,
    }
}

#[derive(Default)]
pub struct Sha1 {
    compressor: Sha1Compressor,
}

impl Sha1 {
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha1Digest` - Object representing the digest operation
    pub fn digest_init<'a>(
        &'a mut self,
        digest: Sha1Digest<'a>,
    ) -> CaliptraResult<Sha1DigestOp<'a>> {
        let op = Sha1DigestOp {
            sha: self,
            state: Sha1DigestState::Init,
            buf: [0u8; SHA1_BLOCK_BYTE_SIZE],
            buf_idx: 0,
            data_size: 0,
            digest,
        };

        Ok(op)
    }

    /// Calculate the digest of the buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to calculate the digest over
    pub fn digest(&mut self, buf: &[u8]) -> CaliptraResult<Array4x5> {
        // Check if the buffer is not large
        if buf.len() > SHA1_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        let mut first = true;
        let mut bytes_remaining = buf.len();

        loop {
            let offset = buf.len() - bytes_remaining;
            match bytes_remaining {
                0..=63 => {
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
                    if let Some(slice) = buf.get(offset..offset + SHA1_BLOCK_BYTE_SIZE) {
                        let block = <&[u8; SHA1_BLOCK_BYTE_SIZE]>::try_from(slice).unwrap();
                        self.digest_block(block, first)?;
                        bytes_remaining -= SHA1_BLOCK_BYTE_SIZE;
                        first = false;
                    } else {
                        raise_err!(InvalidSlice)
                    }
                }
            }
        }

        Ok(self.compressor.hash().into())
    }

    /// Copy digest to buffer
    ///
    /// # Arguments
    ///
    /// * `buf` - Digest buffer
    fn copy_digest_to_buf(&self, buf: &mut Array4x5) -> CaliptraResult<()> {
        *buf = (*self.compressor.hash()).into();
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
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA1_BLOCK_BYTE_SIZE]) {
            let bit_len = (buf_size as u64) << 3;
            block[SHA1_BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        // Construct the block
        let mut block = [0u8; SHA1_BLOCK_BYTE_SIZE];

        // PANIC-FREE: Following check optimizes the out of bounds
        // panic in copy_from_slice
        if slice.len() > block.len() - 1 {
            raise_err!(IndexOutOfBounds)
        }
        block[..slice.len()].copy_from_slice(slice);
        block[slice.len()] = 0b1000_0000;
        if slice.len() < SHA1_BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        // Calculate the digest of the op
        self.digest_block(&block, first)?;

        // Add a padding block if one is needed
        if slice.len() >= SHA1_BLOCK_LEN_OFFSET {
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
        &mut self,
        block: &[u8; SHA1_BLOCK_BYTE_SIZE],
        first: bool,
    ) -> CaliptraResult<()> {
        if first {
            self.compressor.reset()
        }

        self.compressor.compress(block);

        Ok(())
    }
}

/// SHA-256 Digest state
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Sha1DigestState {
    /// Initial state
    Init,

    /// Pending state
    Pending,

    /// Final state
    Final,
}

/// Multi step SHA-256 digest operation
pub struct Sha1DigestOp<'a> {
    /// SHA-256 Engine
    sha: &'a mut Sha1,

    /// State
    state: Sha1DigestState,

    /// Staging buffer
    buf: [u8; SHA1_BLOCK_BYTE_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,

    /// Digest
    digest: Sha1Digest<'a>,
}

impl<'a> Sha1DigestOp<'a> {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state == Sha1DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > SHA1_MAX_DATA_SIZE {
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
        if self.state == Sha1DigestState::Final {
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
        self.state = Sha1DigestState::Final;

        // Copy digest
        self.sha.copy_digest_to_buf(self.digest)?;

        Ok(())
    }

    /// Check if this the first digest operation
    fn is_first(&self) -> bool {
        self.state == Sha1DigestState::Init
    }

    /// Reset internal buffer state
    fn reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Sha1DigestState::Pending;
    }
}

/// SHA1 Compressor
///
/// Implementation based on reference code in https://www.rfc-editor.org/rfc/rfc3174
struct Sha1Compressor {
    /// Hash
    hash: [u32; 5],
}

impl Default for Sha1Compressor {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            hash: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
        }
    }
}

impl Sha1Compressor {
    /// Reset the compressor for new operation
    pub fn reset(&mut self) {
        *self = Sha1Compressor::default()
    }

    /// Compress the block
    ///
    /// Implementation is based on reference code in https://www.rfc-editor.org/rfc/rfc3174
    ///
    /// # Arguments
    ///
    /// * `block` - Block to compress
    pub fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
        let mut w = [0u32; 80];

        // Initialize the first 16 words in
        for idx in 0..16 {
            w[idx] = (block[idx * 4] as u32) << 24;
            w[idx] |= (block[idx * 4 + 1] as u32) << 16;
            w[idx] |= (block[idx * 4 + 2] as u32) << 8;
            w[idx] |= block[idx * 4 + 3] as u32;
        }

        for idx in 16..80 {
            let val = w[idx - 3] ^ w[idx - 8] ^ w[idx - 14] ^ w[idx - 16];
            w[idx] = val.rotate_left(1);
        }

        let mut a = self.hash[0];
        let mut b = self.hash[1];
        let mut c = self.hash[2];
        let mut d = self.hash[3];
        let mut e = self.hash[4];

        for word in w.iter().take(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | ((!b) & d))
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(K[0]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for word in w.iter().take(40).skip(20) {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(K[1]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for word in w.iter().take(60).skip(40) {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(K[2]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for word in w.iter().skip(60) {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(*word)
                .wrapping_add(K[3]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.hash[0] = self.hash[0].wrapping_add(a);
        self.hash[1] = self.hash[1].wrapping_add(b);
        self.hash[2] = self.hash[2].wrapping_add(c);
        self.hash[3] = self.hash[3].wrapping_add(d);
        self.hash[4] = self.hash[4].wrapping_add(e);
    }

    pub fn hash(&self) -> &[u32; 5] {
        &self.hash
    }
}
