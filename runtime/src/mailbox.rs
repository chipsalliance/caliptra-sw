// Licensed under the Apache-2.0 license

use caliptra_registers::mbox::{self, enums::MboxStatusE};

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
    pub fn set_dlen(len: u32) {
        mbox::RegisterBlock::mbox_csr().dlen().write(|_| len);
    }

    // Get the length of the current mailbox data in words
    pub fn dlen_words() -> u32 {
        (Self::dlen() + 7) / 8
    }

    pub fn cmd() -> u32 {
        mbox::RegisterBlock::mbox_csr().cmd().read()
    }

    pub fn copy_from_mbox(buf: &mut [u32]) {
        for word in buf {
            *word = mbox::RegisterBlock::mbox_csr().dataout().read();
        }
    }

    pub fn copy_to_mbox(buf: &[u32]) {
        for word in buf {
            mbox::RegisterBlock::mbox_csr().datain().write(|_| *word);
        }
    }

    pub fn set_status(status: MboxStatusE) {
        mbox::RegisterBlock::mbox_csr()
            .status()
            .write(|w| w.status(|_| status));
    }
}
