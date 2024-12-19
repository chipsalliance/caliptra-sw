/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains API for Mailbox operations

--*/

use crate::memory_layout;
use crate::{CaliptraError, CaliptraResult};
use caliptra_registers::mbox::enums::MboxFsmE;
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_registers::mbox::MboxCsr;
use caliptra_registers::soc_ifc::SocIfcReg;
use core::cmp::min;
use core::mem::size_of;
use core::slice;
use zerocopy::{AsBytes, LayoutVerified, Unalign};

#[derive(Copy, Clone, Default, Eq, PartialEq)]
/// Malbox operational states
pub enum MailboxOpState {
    #[default]
    RdyForCmd,
    RdyForDlen,
    RdyForData,
    Execute,
    Idle,
}

/// Caliptra mailbox abstraction
pub struct Mailbox {
    mbox: MboxCsr,
}

const MAX_MAILBOX_LEN: u32 = 128 * 1024;

impl Mailbox {
    pub fn new(mbox: MboxCsr) -> Self {
        Self { mbox }
    }
    /// Attempt to acquire the lock to start sending data.
    /// # Returns
    /// * `MailboxSendTxn` - Object representing a send operation
    pub fn try_start_send_txn(&mut self) -> Option<MailboxSendTxn> {
        let mbox = self.mbox.regs();
        if mbox.lock().read().lock() {
            None
        } else {
            Some(MailboxSendTxn {
                state: MailboxOpState::default(),
                mbox: &mut self.mbox,
            })
        }
    }

    /// Waits until the uC can acquire the lock to start sending data.
    /// # Returns
    /// * `MailboxSendTxn` - Object representing a send operation
    pub fn wait_until_start_send_txn(&mut self) -> MailboxSendTxn {
        let mbox = self.mbox.regs();
        while mbox.lock().read().lock() {}
        MailboxSendTxn {
            state: MailboxOpState::default(),
            mbox: &mut self.mbox,
        }
    }

    /// Attempts to start receiving data by checking the status.
    /// # Returns
    /// * 'MailboxRecvTxn' - Object representing a receive operation
    pub fn try_start_recv_txn(&mut self) -> Option<MailboxRecvTxn> {
        let mbox = self.mbox.regs();
        match mbox.status().read().mbox_fsm_ps() {
            MboxFsmE::MboxExecuteUc => Some(MailboxRecvTxn {
                state: MailboxOpState::Execute,
                mbox: &mut self.mbox,
            }),
            _ => None,
        }
    }

    /// Lets the caller peek into the mailbox without touching the transaction.
    pub fn peek_recv(&mut self) -> Option<MailboxRecvPeek> {
        let mbox = self.mbox.regs();
        match mbox.status().read().mbox_fsm_ps() {
            MboxFsmE::MboxExecuteUc => Some(MailboxRecvPeek {
                mbox: &mut self.mbox,
            }),
            _ => None,
        }
    }

    /// Aborts with failure any pending SoC->Uc transactions.
    ///
    /// This is useful to call from a fatal-error-handling routine.
    ///
    /// # Safety
    ///
    /// Callers must guarantee that no other code is interacting with the
    /// mailbox at the time this function is called. (For example, any
    /// MailboxRecvTxn and MailboxSendTxn instances have been destroyed or
    /// forgotten).
    ///
    /// This function is safe to call from a trap handler.
    pub unsafe fn abort_pending_soc_to_uc_transactions() {
        let mut mbox = MboxCsr::new();
        if mbox.regs().status().read().mbox_fsm_ps().mbox_execute_uc() {
            // SoC firmware might be stuck waiting for Caliptra to finish
            // executing this pending mailbox transaction. Notify them that
            // we've failed.
            mbox.regs_mut()
                .status()
                .write(|w| w.status(|w| w.cmd_failure()));
        }
    }
}

/// Mailbox send protocol abstraction
pub struct MailboxSendTxn<'a> {
    /// Current state.
    state: MailboxOpState,
    mbox: &'a mut MboxCsr,
}

impl MailboxSendTxn<'_> {
    ///
    /// Transitions from RdyCmd --> RdyForDlen
    ///
    pub fn write_cmd(&mut self, cmd: u32) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForCmd {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        let mbox = self.mbox.regs_mut();

        // Write Command :
        mbox.cmd().write(|_| cmd);

        self.state = MailboxOpState::RdyForDlen;
        Ok(())
    }

    ///
    /// Writes number of bytes to data length register.
    /// Transitions from RdyForDlen --> RdyForData
    ///
    pub fn write_dlen(&mut self, dlen: u32) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForDlen {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        let mbox = self.mbox.regs_mut();

        if dlen > MAX_MAILBOX_LEN {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_DATA_LEN);
        }

        // Write Len in Bytes
        mbox.dlen().write(|_| dlen);

        self.state = MailboxOpState::RdyForData;
        Ok(())
    }

    /// Transitions mailbox to RdyForData state and copies data to mailbox.
    /// * 'cmd' - Command to Be Sent
    /// * 'data' - Data Bufer
    pub fn copy_request(&mut self, cmd: u32, data: &[u8]) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForCmd {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }

        self.write_cmd(cmd)?;

        self.write_dlen(data.len() as u32)?;

        // Copy data to mailbox
        fifo::enqueue(self.mbox, data)?;

        self.state = MailboxOpState::RdyForData;

        Ok(())
    }

    ///
    /// Transitions from RdyForData --> Execute
    ///
    pub fn execute_request(&mut self) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForData {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }

        let mbox = self.mbox.regs_mut();

        // Set Execute Bit
        mbox.execute().write(|w| w.execute(true));

        self.state = MailboxOpState::Execute;

        Ok(())
    }

    /// Send Data to SOC
    /// * 'cmd' - Command to Be Sent
    /// * 'data' - Data Bufer
    pub fn send_request(&mut self, cmd: u32, data: &[u8]) -> CaliptraResult<()> {
        self.copy_request(cmd, data)?;
        self.execute_request()?;
        Ok(())
    }

    /// Checks if receiver processed the request.
    pub fn is_response_ready(&self) -> bool {
        // TODO: Handle MboxStatusE::DataReady
        let mbox = self.mbox.regs();

        matches!(
            mbox.status().read().status(),
            MboxStatusE::CmdComplete | MboxStatusE::CmdFailure
        )
    }

    pub fn status(&self) -> MboxStatusE {
        let mbox = self.mbox.regs();
        mbox.status().read().status()
    }

    ///
    /// Transitions from Execute --> Idle (releases the lock)
    ///
    pub fn complete(&mut self) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        let mbox = self.mbox.regs_mut();
        mbox.execute().write(|w| w.execute(false));
        self.state = MailboxOpState::Idle;
        Ok(())
    }
}

impl Drop for MailboxSendTxn<'_> {
    fn drop(&mut self) {
        let mbox = self.mbox.regs_mut();
        //
        // Release the lock by transitioning the mailbox state machine back
        // to Idle.
        //
        if mbox.status().read().mbox_fsm_ps() != MboxFsmE::MboxIdle {
            mbox.unlock().write(|w| w.unlock(true));
        }
    }
}

pub struct MailboxRecvPeek<'a> {
    mbox: &'a mut MboxCsr,
}
impl<'a> MailboxRecvPeek<'a> {
    /// Returns the value stored in the command register
    pub fn cmd(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.cmd().read()
    }

    /// Returns the value stored in the user register
    pub fn id(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.user().read()
    }

    /// Returns the value stored in the data length register. This is the total
    /// size of the mailbox data in bytes.
    pub fn dlen(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.dlen().read()
    }

    pub fn start_txn(self) -> MailboxRecvTxn<'a> {
        MailboxRecvTxn {
            state: MailboxOpState::Execute,
            mbox: self.mbox,
        }
    }
}

/// Mailbox Fifo abstraction
mod fifo {
    use super::*;

    fn dequeue_words(mbox: &mut MboxCsr, buf: &mut [Unalign<u32>]) {
        let mbox = mbox.regs_mut();
        for word in buf.iter_mut() {
            *word = Unalign::new(mbox.dataout().read());
        }
    }
    pub fn dequeue(mbox: &mut MboxCsr, mut buf: &mut [u8]) {
        let dlen_bytes = mbox.regs().dlen().read() as usize;
        if dlen_bytes < buf.len() {
            buf = &mut buf[..dlen_bytes];
        }

        let len_words = buf.len() / size_of::<u32>();
        let (mut buf_words, suffix) =
            LayoutVerified::new_slice_unaligned_from_prefix(buf, len_words).unwrap();

        dequeue_words(mbox, &mut buf_words);
        if !suffix.is_empty() {
            let last_word = mbox.regs().dataout().read();
            let suffix_len = suffix.len();
            suffix
                .as_bytes_mut()
                .copy_from_slice(&last_word.as_bytes()[..suffix_len]);
        }
    }

    fn enqueue_words(mbox: &mut MboxCsr, buf: &[Unalign<u32>]) {
        let mbox = mbox.regs_mut();
        for word in buf {
            mbox.datain().write(|_| word.get());
        }
    }

    /// Writes buf.len() bytes to the mailbox datain reg as dwords
    #[inline(never)]
    pub fn enqueue(mbox: &mut MboxCsr, buf: &[u8]) -> CaliptraResult<()> {
        if mbox.regs().dlen().read() as usize != buf.len() {
            return Err(CaliptraError::DRIVER_MAILBOX_ENQUEUE_ERR);
        }

        let (buf_words, suffix) =
            LayoutVerified::new_slice_unaligned_from_prefix(buf, buf.len() / size_of::<u32>())
                .unwrap();
        enqueue_words(mbox, &buf_words);
        if !suffix.is_empty() {
            let mut last_word = 0_u32;
            last_word.as_bytes_mut()[..suffix.len()].copy_from_slice(suffix);
            enqueue_words(mbox, &[Unalign::new(last_word)]);
        }

        Ok(())
    }
}

/// Mailbox recveive protocol abstraction
pub struct MailboxRecvTxn<'a> {
    /// Current state of transaction
    state: MailboxOpState,

    mbox: &'a mut MboxCsr,
}

impl MailboxRecvTxn<'_> {
    /// Returns the value stored in the command register
    pub fn cmd(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.cmd().read()
    }

    /// Returns the value stored in the data length register. This is the total
    /// size of the mailbox data in bytes.
    pub fn dlen(&self) -> u32 {
        let mbox = self.mbox.regs();
        mbox.dlen().read()
    }

    /// Provides direct access to entire mailbox SRAM.
    pub fn raw_mailbox_contents(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                memory_layout::MBOX_ORG as *const u8,
                memory_layout::MBOX_SIZE as usize,
            )
        }
    }

    /// Pulls at most `count` words from the mailbox and throws them away
    pub fn drop_words(&mut self, count: usize) -> CaliptraResult<()> {
        let mbox = self.mbox.regs_mut();
        let dlen_bytes = mbox.dlen().read() as usize;
        let dlen_words = (dlen_bytes + 3) / 4;
        let words_to_read = min(count, dlen_words);
        for _ in 0..words_to_read {
            _ = mbox.dataout().read();
        }

        Ok(())
    }

    /// Writes number of bytes to data length register.
    fn write_dlen(&mut self, dlen: u32) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForDlen {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        let mbox = self.mbox.regs_mut();

        if dlen > MAX_MAILBOX_LEN {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_DATA_LEN);
        }

        // Write Len in Bytes
        mbox.dlen().write(|_| dlen);
        Ok(())
    }

    /// Pulls at most `(data.len() + 3) / 4` words from the mailbox FIFO without
    /// performing state transition.
    ///
    /// # Arguments
    ///
    /// * `data` - data buffer.
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///
    pub fn copy_request(&mut self, data: &mut [u8]) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        fifo::dequeue(self.mbox, data);
        if mailbox_uncorrectable_ecc() {
            return Err(CaliptraError::DRIVER_MAILBOX_UNCORRECTABLE_ECC);
        }
        Ok(())
    }

    /// Pulls at most `(data.len() + 3) / 4` words from the mailbox FIFO.
    /// Transitions from Execute --> Idle (releases the lock)
    ///
    /// # Arguments
    ///
    /// * `data` - data buffer.
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///
    pub fn recv_request(&mut self, data: &mut [u8]) -> CaliptraResult<()> {
        self.copy_request(data)?;
        self.complete(true)
    }

    /// Sends `data.len()` bytes to the mailbox FIFO
    /// Transitions from Execute --> RdyForData
    ///
    /// # Arguments
    ///
    /// * `data` - data buffer.
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///
    fn copy_response(&mut self, data: &[u8]) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }

        self.state = MailboxOpState::RdyForDlen;
        // Set dlen
        self.write_dlen(data.len() as u32)?;

        self.state = MailboxOpState::RdyForData;
        // Copy the data
        fifo::enqueue(self.mbox, data)
    }

    /// Sends `data.len()` bytes to the mailbox FIFO.
    /// Transitions from Execute --> Idle (releases the lock)
    ///
    /// # Arguments
    ///
    /// * `data` - data buffer.
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///
    pub fn send_response(&mut self, data: &[u8]) -> CaliptraResult<()> {
        self.copy_response(data)?;
        self.complete(true)
    }

    ///
    /// Transitions from Execute or RdyForData-> Idle
    ///
    /// Does not take ownership of self, unlike complete()
    pub fn complete(&mut self, success: bool) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute && self.state != MailboxOpState::RdyForData {
            return Err(CaliptraError::DRIVER_MAILBOX_INVALID_STATE);
        }
        let status = if success {
            if self.state == MailboxOpState::RdyForData {
                MboxStatusE::DataReady
            } else {
                MboxStatusE::CmdComplete
            }
        } else {
            MboxStatusE::CmdFailure
        };

        let mbox = self.mbox.regs_mut();
        mbox.status().write(|w| w.status(|_| status));

        self.state = MailboxOpState::Idle;
        Ok(())
    }

    ///
    /// Set UC TAP unlock
    ///
    pub fn set_uc_tap_unlock(&mut self, enable: bool) {
        let mbox = self.mbox.regs_mut();
        mbox.tap_mode().modify(|w| w.enabled(enable))
    }
}

impl Drop for MailboxRecvTxn<'_> {
    fn drop(&mut self) {
        if self.state != MailboxOpState::Idle {
            // Execute -> Idle (releases lock)
            let _ = self.complete(false);
        }
    }
}

fn mailbox_uncorrectable_ecc() -> bool {
    unsafe {
        SocIfcReg::new()
            .regs()
            .intr_block_rf()
            .error_internal_intr_r()
            .read()
            .error_mbox_ecc_unc_sts()
    }
}
