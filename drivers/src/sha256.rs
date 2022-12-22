/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256.rs

Abstract:

    File contains API for SHA-256 Cryptography operations

--*/

use crate::reg::sha256_regs::*;
use crate::slice::{CopyFromByteSlice, CopyFromReadOnlyRegisterArray};
use crate::{cptr_err_def, CptrResult};
use tock_registers::interfaces::{Readable, Writeable};

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_HASH_SIZE: usize = 32;
const SHA256_MAX_DATA_SIZE: usize = 1024 * 1024;
type Sha256Hash = [u8; SHA256_HASH_SIZE];

cptr_err_def! {
    Sha256,
    Sha256Err
    {
        // Invalid state
        InvalidStateErr = 0x1,

        // Max data limit reached
        MaxDataErr = 0x2,

        //Invalid Digest Buffer
        InvalidDigestBuffer = 0x3,

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
}

/// Multi step SHA-256 digest operation
pub struct Sha256DigestOp {
    /// State
    state: Sha256DigestState,

    /// Staging buffer
    buf: [u8; SHA256_BLOCK_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,
}

impl Sha256DigestOp {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CptrResult<()> {
        if self.state == Sha256DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > SHA256_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        for byte in data {
            self.data_size += 1;

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the digest of accumulated data
            if self.buf_idx == self.buf.len() {
                Sha256::_digest_block(&self.buf, self._is_init());
                self._reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    ///
    /// # Returns
    ///
    /// * `[u8; SHA256_HASH_SIZE]` - The digest of the data
    /// * `usize`   -  The size of the digest generated
    ///
    pub fn finalize(&mut self, digest: &mut Sha256Hash) -> CptrResult<()> {
        if self.state == Sha256DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if digest.len() != SHA256_HASH_SIZE {
            raise_err!(InvalidDigestBuffer)
        }

        // Calculate the digest of the final block
        let buf = &self.buf[..self.buf_idx];
        Sha256::_digest_last_block(buf, self._is_init(), self.data_size);

        // Set the state of the operation to final
        self.state = Sha256DigestState::Final;

        // Copy the digest from the register
        digest.copy_from_ro_reg(&SHA256_REGS.digest);

        Ok(())
    }

    #[inline]
    fn _is_init(&self) -> bool {
        if self.state == Sha256DigestState::Init {
            true
        } else {
            false
        }
    }

    #[inline]
    fn _reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Sha256DigestState::Pending;
    }
}

pub enum Sha256 {}

impl Sha256 {
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha256Digest` - Object representing the digest operation
    pub fn init_digest() -> Sha256DigestOp {
        Sha256DigestOp {
            state: Sha256DigestState::Init,
            buf: [0u8; SHA256_BLOCK_SIZE],
            buf_idx: 0,
            data_size: 0,
        }
    }

    /// Calculate the digest for specified data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    ///
    /// # Returns
    ///
    /// * `[u8; SHA256_HASH_SIZE]` - The digest of the data
    /// * `usize`   -  The size of the digest generated.
    ///
    pub fn digest(data: &[u8], digest: &mut Sha256Hash) -> CptrResult<()> {
        if data.len() > SHA256_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        if digest.len() != SHA256_HASH_SIZE {
            raise_err!(InvalidDigestBuffer)
        }

        let mut init = true;
        let mut bytes_remaining = data.len();

        loop {
            let offset = data.len() - bytes_remaining;
            match bytes_remaining {
                0..=63 => {
                    Self::_digest_last_block(&data[offset..], init, data.len());
                    break;
                }
                _ => {
                    Self::_digest_block(&data[offset..offset + SHA256_BLOCK_SIZE], init);
                    bytes_remaining -= SHA256_BLOCK_SIZE;
                    init = false;
                }
            }
        }
        digest.copy_from_ro_reg(&SHA256_REGS.digest);
        Ok(())
    }

    fn _digest_last_block(buf: &[u8], init: bool, buf_size: usize) {
        #[inline]
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA256_BLOCK_SIZE]) {
            let bit_len = (buf_size as u64) << 3;
            block[BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        const BLOCK_LEN_OFFSET: usize = 56;
        let mut block = [0u8; SHA256_BLOCK_SIZE];
        block[..buf.len()].copy_from_slice(&buf);
        block[buf.len()] = 0b1000_0000;

        if buf.len() < BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut block);
        }

        Self::_digest_block(&block, init);

        if buf.len() >= BLOCK_LEN_OFFSET {
            block.fill(0);
            set_block_len(buf_size, &mut block);
            Self::_digest_block(&block, false);
        }
    }

    fn _digest_block(block: &[u8], init: bool) {
        #[inline]
        fn init_digest() {
            SHA256_REGS
                .control
                .write(CONTROL::MODE::SHA256 + CONTROL::INIT::SET + CONTROL::NEXT::CLEAR);
        }

        #[inline]
        fn update_digest() {
            SHA256_REGS
                .control
                .write(CONTROL::MODE::SHA256 + CONTROL::INIT::CLEAR + CONTROL::NEXT::SET);
        }

        #[inline]
        fn wait_for_hw_ready() {
            while !SHA256_REGS.status.is_set(STATUS::READY) {}
        }

        #[inline]
        fn wait_for_digest() {
            while !SHA256_REGS.status.is_set(STATUS::VALID) {}
        }

        wait_for_hw_ready();

        SHA256_REGS.block.copy_from_byte_slice(block);

        if init {
            init_digest();
        } else {
            update_digest();
        }

        wait_for_digest()
    }
}
