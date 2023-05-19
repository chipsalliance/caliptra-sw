// Licensed under the Apache-2.0 license

use crate::RuntimeErr;
use caliptra_drivers::CaliptraResult;
use caliptra_registers::mbox::{enums::MboxStatusE, MboxCsr};
use zerocopy::{LayoutVerified, Unalign};

pub struct Mailbox {
    mbox: MboxCsr,
}

impl Mailbox {
    pub fn new(mbox: MboxCsr) -> Self {
        Self { mbox }
    }
    /// Check if there is a new command to be executed
    pub fn is_cmd_ready(&mut self) -> bool {
        let mbox = self.mbox.regs();
        mbox.status().read().mbox_fsm_ps().mbox_execute_uc()
    }

    // Get the length of the current mailbox data in bytes
    pub fn dlen(&mut self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.dlen().read()
    }

    // Set the length of the current mailbox data in bytes
    pub fn _set_dlen(&mut self, len: u32) {
        let mbox = self.mbox.regs_mut();
        mbox.dlen().write(|_| len);
    }

    // Get the length of the current mailbox data in words
    pub fn dlen_words(&mut self) -> u32 {
        (self.dlen() + 3) / 4
    }

    pub fn cmd(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.cmd().read()
    }

    pub fn copy_from_mbox(&mut self, buf: &mut [u32]) {
        let mbox = self.mbox.regs_mut();
        for word in buf {
            *word = mbox.dataout().read();
        }
    }

    pub fn _copy_to_mbox(&mut self, buf: &[Unalign<u32>]) {
        let mbox = self.mbox.regs_mut();
        for word in buf {
            mbox.datain().write(|_| word.get());
        }
    }

    /// Write a word-aligned `buf` to the mailbox
    pub fn _write_response(&mut self, buf: &[u8]) -> CaliptraResult<()> {
        let Some(buf_words) = LayoutVerified::new_slice_unaligned(buf) else {
            // buf size is not a multiple of word size
            return Err(RuntimeErr::InternalErr.into());
        };

        self._set_dlen(buf.len() as u32);
        self._copy_to_mbox(&buf_words);

        Ok(())
    }

    pub fn set_status(&mut self, status: MboxStatusE) {
        let mbox = self.mbox.regs_mut();
        mbox.status().write(|w| w.status(|_| status));
    }
}
