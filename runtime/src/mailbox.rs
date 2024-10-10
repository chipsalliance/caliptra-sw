/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains mailbox interface.

--*/

use core::mem::size_of;
use core::slice;

use caliptra_drivers::{memory_layout, CaliptraResult};
use caliptra_error::CaliptraError;
use caliptra_registers::mbox::{
    enums::{MboxFsmE, MboxStatusE},
    MboxCsr,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::CommandId;

pub struct Mailbox {
    mbox: MboxCsr,
}

impl Mailbox {
    /// Create a new Mailbox
    pub fn new(mbox: MboxCsr) -> Self {
        Self { mbox }
    }

    /// Check if there is a new command to be executed
    pub fn is_cmd_ready(&self) -> bool {
        let mbox = self.mbox.regs();
        mbox.status().read().mbox_fsm_ps().mbox_execute_uc()
    }

    /// Check if we are currently executing a mailbox command
    pub fn cmd_busy(&self) -> bool {
        let mbox = self.mbox.regs();
        mbox.status().read().status().cmd_busy()
    }

    /// Get the length of the current mailbox data in bytes
    pub fn dlen(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.dlen().read()
    }

    /// Set the length of the current mailbox data in bytes
    pub fn set_dlen(&mut self, len: u32) -> CaliptraResult<()> {
        if len > memory_layout::MBOX_SIZE {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let mbox = self.mbox.regs_mut();
        mbox.dlen().write(|_| len);
        Ok(())
    }

    /// Get the length of the current mailbox data in words
    pub fn dlen_words(&self) -> u32 {
        (self.dlen() + 3) / 4
    }

    /// Get the CommandId from the mailbox
    pub fn cmd(&self) -> CommandId {
        let mbox = self.mbox.regs();
        let cmd_code = mbox.cmd().read();

        CommandId(cmd_code)
    }

    /// Lock the mailbox
    pub fn lock(&mut self) -> bool {
        let mbox = self.mbox.regs();
        mbox.lock().read().lock()
    }

    /// Unlock the mailbox
    pub fn unlock(&mut self) {
        let mbox = self.mbox.regs_mut();
        mbox.unlock().write(|_| 1.into());
    }

    /// Writes command `cmd` ot the mailbox if it is ready for a command
    pub fn write_cmd(&mut self, cmd: u32) -> CaliptraResult<()> {
        let mbox = self.mbox.regs_mut();
        match mbox.status().read().mbox_fsm_ps() {
            MboxFsmE::MboxRdyForCmd => {
                mbox.cmd().write(|_| cmd);
                Ok(())
            }
            _ => Err(CaliptraError::RUNTIME_INTERNAL),
        }
    }

    /// Gets the user of the mailbox
    pub fn user(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.user().read()
    }

    /// Copies data in mailbox to `buf`
    pub fn copy_from_mbox(&mut self, buf: &mut [u32]) {
        let mbox = self.mbox.regs_mut();
        for word in buf {
            *word = mbox.dataout().read();
        }
    }

    /// Clears the mailbox
    pub fn flush(&mut self) {
        let count = self.dlen_words();
        let mbox = self.mbox.regs_mut();
        for _ii in 0..count {
            let _ = mbox.dataout().read();
        }
    }

    /// Copies `buf` to the mailbox
    pub fn copy_words_to_mbox(&mut self, buf: &[u32]) {
        let mbox = self.mbox.regs_mut();
        for word in buf {
            mbox.datain().write(|_| *word);
        }
    }

    /// Copies word-aligned `buf` to the mailbox
    pub fn copy_bytes_to_mbox(&mut self, buf: &[u8]) -> CaliptraResult<()> {
        let count = buf.len() / size_of::<u32>();
        let (buf_words, suffix) =
            <[u32]>::ref_from_prefix_with_elems(buf, count).map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
        self.copy_words_to_mbox(&buf_words);
        if !suffix.is_empty() {
            if let Ok(last_word) = u32::ref_from_bytes(suffix) {
                self.copy_words_to_mbox(&[*last_word]);
            }
        }
        Ok(())
    }

    /// Write a word-aligned `buf` to the mailbox
    pub fn write_response(&mut self, buf: &[u8]) -> CaliptraResult<()> {
        self.set_dlen(buf.len() as u32)?;
        self.copy_bytes_to_mbox(buf);
        Ok(())
    }

    /// Set mailbox status to `status`
    pub fn set_status(&mut self, status: MboxStatusE) {
        let mbox = self.mbox.regs_mut();
        mbox.status().write(|w| w.status(|_| status));
    }

    /// Retrieve a slice with the contents of the mailbox
    pub fn raw_mailbox_contents(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                memory_layout::MBOX_ORG as *const u8,
                memory_layout::MBOX_SIZE as usize,
            )
        }
    }
}
