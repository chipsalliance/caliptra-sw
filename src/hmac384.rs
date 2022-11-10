/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384.rs

Abstract:

    File contains API for HMAC-384 Cryptography operations

--*/
use crate::reg::hmac384_regs::*;
use crate::slice::{CopyFromByteSlice, CopyFromReadOnlyRegisterArray};
use crate::{cptr_err_def, CptrResult};
use tock_registers::interfaces::{Readable, Writeable};

type HmacKey = [u8; HMAC384_KEY_SIZE];
type HmacTag = [u8; HMAC384_TAG_SIZE];

const HMAC384_BLOCK_SIZE: usize = 128;
const HMAC384_TAG_SIZE: usize = 48;
const HMAC384_MAX_DATA_SIZE: usize = 1024 * 1024;
const HMAC384_KEY_SIZE: usize = 48;

cptr_err_def! {
    Hmac384,
    Hmac384Err
    {
        // Invalid state
        InvalidStateErr = 0x1,

        // Max data limit reached
        MaxDataErr = 0x2,

        // Tag Buffer Size Error
        InvalidTagBuffer = 0x3,
    }
}

/// HMAC operation state
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
pub struct Hmac384Op {
    /// State
    state: Hmac384OpState,

    /// Staging buffer
    buf: [u8; HMAC384_BLOCK_SIZE],

    /// Current staging buffer index
    buf_idx: usize,

    /// Data size
    data_size: usize,
}

impl Hmac384Op {
    /// Update the HMAC with data
    ///
    /// # Arguments
    ///
    /// * `data` - Data to used to update the digest
    pub fn update(&mut self, data: &[u8]) -> CptrResult<()> {
        if self.state == Hmac384OpState::Final {
            raise_err!(InvalidStateErr)
        }

        if self.data_size + data.len() > HMAC384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        for byte in data {
            self.data_size += 1;

            // Copy the data to the buffer
            self.buf[self.buf_idx] = *byte;
            self.buf_idx += 1;

            // If the buffer is full calculate the hash of accumulated data
            if self.buf_idx == self.buf.len() {
                Hmac384::_hmac_block(&self.buf, self._is_init());
                self._reset_buf_state();
            }
        }

        Ok(())
    }

    /// Finalize the HMAC operations
    ///
    /// # Returns
    ///
    /// * `HmacTag` - HMAC Tag is returned in  the provided "out_tag" buffer
    /// * usize     - is returned as a part of CptrResult indicating the size of the tag generated.
    ///
    pub fn finalize(&mut self, out_tag: &mut HmacTag) -> CptrResult<usize> {
        if self.state == Hmac384OpState::Final {
            raise_err!(InvalidStateErr)
        }

        if out_tag.len() != HMAC384_TAG_SIZE {
            raise_err!(InvalidTagBuffer)
        }

        // Calculate the hash of the final block
        let buf = &self.buf[..self.buf_idx];
        Hmac384::_hmac_last_block(buf, self._is_init(), self.data_size);

        // Set the state of the operation to final
        self.state = Hmac384OpState::Final;

        // Copy the hash from the register
        out_tag.copy_from_ro_reg(&HMAC384_REGS.tag);

        Ok(out_tag.len())
    }

    #[inline]
    fn _is_init(&self) -> bool {
        if self.state == Hmac384OpState::Init {
            true
        } else {
            false
        }
    }

    #[inline]
    fn _reset_buf_state(&mut self) {
        self.buf.fill(0);
        self.buf_idx = 0;
        self.state = Hmac384OpState::Pending;
    }
}

pub enum Hmac384 {}

impl Hmac384 {
    /// Initialize multi step HMAC operation
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC Key
    ///
    /// # Returns
    ///
    /// * `Hmac384Op` - Object representing the digest operation
    pub fn hmac_init(key: &HmacKey) -> Hmac384Op {
        // Write the key to the hardware
        HMAC384_REGS.key.copy_from_byte_slice(key);

        Hmac384Op {
            state: Hmac384OpState::Init,
            buf: [0u8; HMAC384_BLOCK_SIZE],
            buf_idx: 0,
            data_size: 0,
        }
    }

    /// Calculate the HMAC of the data using specified key
    ///
    /// # Arguments
    ///
    /// * `key`     - HMAC Key
    /// * `data`    - Data to calculate the HMAC
    /// * `tag`     - Buffer to return the hmac tag
    /// # Returns
    ///
    /// * hmac_tag  - Returns the generated tag in the "hmac_tag" buffer
    /// * usize on success which is the size of the generated tag
    ///

    pub fn hmac(key: &HmacKey, data: &[u8], hmac_tag: &mut HmacTag) -> CptrResult<usize> {
        if data.len() >= HMAC384_MAX_DATA_SIZE {
            raise_err!(MaxDataErr)
        }

        if hmac_tag.len() != HMAC384_TAG_SIZE {
            raise_err!(InvalidTagBuffer);
        }

        // Write the HMAC key to the hardware
        HMAC384_REGS.key.copy_from_byte_slice(key);

        let mut init = true;
        let mut bytes_remaining = data.len();

        loop {
            let offset = data.len() - bytes_remaining;

            match bytes_remaining {
                0..=127 => {
                    Self::_hmac_last_block(&data[offset..], init, data.len());
                    break;
                }
                _ => {
                    Self::_hmac_block(&data[offset..(offset + HMAC384_BLOCK_SIZE)], init);
                    bytes_remaining -= HMAC384_BLOCK_SIZE;
                    init = false;
                }
            }
        }

        hmac_tag.copy_from_ro_reg(&HMAC384_REGS.tag);
        Ok(hmac_tag.len())
    }

    fn _hmac_last_block(buf: &[u8], init: bool, buf_size: usize) {
        const BLOCK_LEN_OFFSET: usize = 112;

        #[inline]
        fn set_block_len(buf_size: usize, data_block: &mut [u8; 128]) {
            let bit_len = ((buf_size + HMAC384_BLOCK_SIZE) as u128) << 3;
            data_block[BLOCK_LEN_OFFSET..].copy_from_slice(&bit_len.to_be_bytes());
        }

        let mut data_block = [0u8; HMAC384_BLOCK_SIZE];
        data_block[..buf.len()].copy_from_slice(&buf);
        data_block[buf.len()] = 0b1000_0000;

        if buf.len() < BLOCK_LEN_OFFSET {
            set_block_len(buf_size, &mut data_block);
        }

        Self::_hmac_block(&data_block, init);

        if buf.len() >= BLOCK_LEN_OFFSET {
            data_block.fill(0);
            set_block_len(buf_size, &mut data_block);
            Self::_hmac_block(&data_block, false);
        }
    }

    fn _hmac_block(data_block: &[u8], init: bool) {
        #[inline]
        fn init_hash_block() {
            HMAC384_REGS
                .control
                .write(CONTROL::INIT::SET + CONTROL::NEXT::CLEAR);
        }

        #[inline]
        fn update_hash_block() {
            HMAC384_REGS
                .control
                .write(CONTROL::INIT::CLEAR + CONTROL::NEXT::SET);
        }

        #[inline]
        fn wait_for_hw_ready() {
            while !HMAC384_REGS.status.is_set(STATUS::READY) {}
        }

        #[inline]
        fn wait_for_tag() {
            while !HMAC384_REGS.status.is_set(STATUS::VALID) {}
        }

        wait_for_hw_ready();

        HMAC384_REGS.block.copy_from_byte_slice(data_block);

        if init {
            init_hash_block();
        } else {
            update_hash_block();
        }

        wait_for_tag()
    }
}
