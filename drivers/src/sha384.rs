/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384.rs

Abstract:

    File contains API for SHA-384 Cryptography operations

--*/

use crate::reg::sha512_regs::*;
use crate::slice::{CopyFromByteSlice, CopyFromReadOnlyRegisterArray};
use crate::{cptr_err_def, CptrResult};
use tock_registers::interfaces::{Readable, Writeable};

const SHA384_BLOCK_SIZE: usize = 128;
const SHA384_HASH_SIZE: usize = 48;
const SHA384_MAX_DATA_SIZE: usize = 1024 * 1024;
type Sha384Hash = [u8; SHA384_HASH_SIZE];

cptr_err_def! {
    Sha384,
    Sha384Err
    {
        // Invalid state
        InvalidStateErr = 0x1,

        // Max data limit reached
        MaxDataErr = 0x2,

        // Invalid Digest Buffer
        InvalidDigestBuffer = 0x3,
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
pub struct Sha384DigestOp {
    /// State
    state: Sha384DigestState,

    /// Staging buffer
    buf: [u8; SHA384_BLOCK_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,
}

impl Sha384DigestOp {
    /// Update the digest with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CptrResult<()> {
        if self.state == Sha384DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > SHA384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        for byte in data {
            self.data_size += 1;

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the digest of accumulated data
            if self.buf_idx == self.buf.len() {
                Sha384::_digest_block(&self.buf, self._is_init());
                self._reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the digest operations
    ///
    /// # Returns
    ///
    /// * `[u8; SHA384_HASH_SIZE]` - The digest of the data
    /// * `usize`   - The size of the digest generated
    ///
    pub fn finalize(&mut self, digest: &mut Sha384Hash) -> CptrResult<()> {
        if self.state == Sha384DigestState::Final {
            raise_err!(InvalidStateErr)
        }

        if digest.len() != SHA384_HASH_SIZE {
            raise_err!(InvalidDigestBuffer)
        }

        // Calculate the digest of the final block
        let buf = &self.buf[..self.buf_idx];
        Sha384::_digest_last_block(buf, self._is_init(), self.data_size);

        // Set the state of the operation to final
        self.state = Sha384DigestState::Final;

        // Copy the digest from the register
        digest.copy_from_ro_reg(&SHA512_REGS.digest);

        Ok(())
    }

    #[inline]
    fn _is_init(&self) -> bool {
        if self.state == Sha384DigestState::Init {
            true
        } else {
            false
        }
    }

    #[inline]
    fn _reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Sha384DigestState::Pending;
    }
}

pub enum Sha384 {}

impl Sha384 {
    /// Initialize multi step digest operation
    ///
    /// # Returns
    ///
    /// * `Sha384Digest` - Object representing the digest operation
    pub fn init_digest() -> Sha384DigestOp {
        Sha384DigestOp {
            state: Sha384DigestState::Init,
            buf: [0u8; SHA384_BLOCK_SIZE],
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
    /// * `[u8; SHA384_HASH_SIZE]` - The digest of the data
    /// * `usize` - The size of the digest data
    pub fn digest(data: &[u8], digest: &mut Sha384Hash) -> CptrResult<()> {
        if data.len() > SHA384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        if digest.len() != SHA384_HASH_SIZE {
            raise_err!(InvalidDigestBuffer)
        }

        let mut init = true;
        let mut bytes_remaining = data.len();

        loop {
            let offset = data.len() - bytes_remaining;
            match bytes_remaining {
                0..=127 => {
                    Self::_digest_last_block(&data[offset..], init, data.len());
                    break;
                }
                _ => {
                    Self::_digest_block(&data[offset..offset + SHA384_BLOCK_SIZE], init);
                    bytes_remaining -= SHA384_BLOCK_SIZE;
                    init = false;
                }
            }
        }
        digest.copy_from_ro_reg(&SHA512_REGS.digest);
        Ok(())
    }

    fn _digest_last_block(buf: &[u8], init: bool, buf_size: usize) {
        #[inline]
        fn set_block_len(buf_size: usize, block: &mut [u8; SHA384_BLOCK_SIZE]) {
            let bit_len = (buf_size as u128) << 3;
            block[BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        const BLOCK_LEN_OFFSET: usize = 112;
        let mut block = [0u8; SHA384_BLOCK_SIZE];
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
            SHA512_REGS
                .control
                .write(CONTROL::MODE::SHA384 + CONTROL::INIT::SET + CONTROL::NEXT::CLEAR);
        }

        #[inline]
        fn update_digest() {
            SHA512_REGS
                .control
                .write(CONTROL::MODE::SHA384 + CONTROL::INIT::CLEAR + CONTROL::NEXT::SET);
        }

        #[inline]
        fn wait_for_hw_ready() {
            while !SHA512_REGS.status.is_set(STATUS::READY) {}
        }

        #[inline]
        fn wait_for_digest() {
            while !SHA512_REGS.status.is_set(STATUS::VALID) {}
        }

        wait_for_hw_ready();

        SHA512_REGS.block.copy_from_byte_slice(block);

        if init {
            init_digest();
        } else {
            update_digest();
        }

        wait_for_digest()
    }
}
