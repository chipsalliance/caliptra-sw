// Licensed under the Apache-2.0 license

use crate::RuntimeErr;
use caliptra_drivers::CaliptraResult;
use caliptra_registers::mbox::{self, enums::MboxStatusE};
use zerocopy::{LayoutVerified, Unalign};

pub struct Mailbox {}

impl Mailbox {
    /// Check if there is a new command to be executed
    pub fn is_cmd_ready() -> bool {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.status().read().mbox_fsm_ps().mbox_execute_uc()
    }

    // Get the length of the current mailbox data in bytes
    pub fn dlen() -> u32 {
        mbox::RegisterBlock::mbox_csr().dlen().read()
    }

    // Set the length of the current mailbox data in bytes
    pub fn _set_dlen(len: u32) {
        mbox::RegisterBlock::mbox_csr().dlen().write(|_| len);
    }

    // Get the length of the current mailbox data in words
    pub fn dlen_words() -> u32 {
        (Self::dlen() + 3) / 4
    }

    pub fn cmd() -> u32 {
        mbox::RegisterBlock::mbox_csr().cmd().read()
    }

    pub fn copy_from_mbox(buf: &mut [u32]) {
        for word in buf {
            *word = mbox::RegisterBlock::mbox_csr().dataout().read();
        }
    }

    pub fn _copy_to_mbox(buf: &[Unalign<u32>]) {
        for word in buf {
            mbox::RegisterBlock::mbox_csr()
                .datain()
                .write(|_| word.get());
        }
    }

    /// Write a word-aligned `buf` to the mailbox
    pub fn _write_response(buf: &[u8]) -> CaliptraResult<()> {
        let Some(buf_words) = LayoutVerified::new_slice_unaligned(buf) else {
            // buf size is not a multiple of word size
            return Err(RuntimeErr::InternalErr.into());
        };

        Self::_set_dlen(buf.len() as u32);
        Self::_copy_to_mbox(&buf_words);

        Ok(())
    }

    pub fn set_status(status: MboxStatusE) {
        mbox::RegisterBlock::mbox_csr()
            .status()
            .write(|w| w.status(|_| status));
    }
}
