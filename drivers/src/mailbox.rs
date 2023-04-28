//! Licensed under the Apache-2.0 license.
//! file : mailbox.rs
//! Abstract:
//!    File contains mailbox abstraction.
//!   The mailbox is the interface for the SoC to communicate with the Caliptra iRot.
//!   The mailbox is used to send commands to the Caliptra iRot and to receive responses.

use crate::{caliptra_err_def, CaliptraResult};
use caliptra_registers::mbox::enums::MboxFsmE;
use caliptra_registers::mbox::{self, enums::MboxStatusE};
use core::cmp::min;
use core::mem::size_of;

caliptra_err_def! {
    Mailbox,
    MailboxErr
    {
        // Exceeds mailbox capacity
        InvalidDlenErr = 0x1,
        EnqueueErr = 0x02,
        MailboxAccessErr = 0x03,
    }
}

/// Mailbox operational states.
/// These are used to implement the typestate pattern.
/// See https://rust-embedded.github.io/book/patterns/typestate.html
/// for more information.
/// The typestate pattern is used to statically enforce the correct
/// order of mailbox operations.
/// For example, the MailboxSendTxn type can only transition from
/// the RdyForCmd state to the RdyForDlen state.
/// This prevents the user from writing a data length before a command.
///
/// The typestate pattern is implemented using the following structs.
/// Each struct represents a state and contains a method for each
/// possible transition to another state.
/// The method names are the same as the next state.
/// For example, the RdyForCmd struct contains a method called
/// write_cmd that transitions to the RdyForDlen state.

/// Idle is the initial state of the mailbox, when it is unlocked.
/// The mailbox is locked when a transaction is in progress.
/// The mailbox is unlocked when the transaction is complete.
///
/// Idle is the initial state of the mailbox, when it is unlocked.
pub struct RdyForCmd;
pub struct RdyForDlen;
pub struct RdyForData;
pub struct Execute;
#[derive(Default)]
/// Caliptra mailbox abstraction
pub struct Mailbox {}

const MAX_MAILBOX_LEN: u32 = 128 * 1024;

impl Mailbox {
    pub fn send_request(&self, cmd: u32, data: &[u8]) -> CaliptraResult<MailboxSendTxn<Execute>> {
        if let Some(txn) = self.try_start_send_txn() {
            let txn = txn
                .write_cmd(cmd)
                .try_write_dlen((data.len()) as u32)?
                .try_write_data(data)?;
            Ok(txn.execute())
        } else {
            raise_err!(MailboxAccessErr)
        }
    }

    /// Attempt to acquire the lock to start sending data.
    /// # Returns
    /// * `MailboxSendTxn` - Object representing a send operation
    /// * `None` - If the mailbox is locked
    /// # Example
    /// ```
    /// let mut mb = Mailbox::default();
    /// let txn = mb.try_start_send_txn().unwrap_or_else(|| panic!("Mailbox is locked"));
    /// ```
    pub fn try_start_send_txn(&self) -> Option<MailboxSendTxn<RdyForCmd>> {
        let mbox = mbox::RegisterBlock::mbox_csr();
        if mbox.lock().read().lock() {
            None
        } else {
            Some(MailboxSendTxn::default())
        }
    }
    /// Attempts to start receiving data by checking the status.
    /// # Returns
    /// * 'MailboxRecvTxn' - Object representing a receive operation
    pub fn try_start_recv_txn(&self) -> Option<MailboxRecvTxn> {
        let mbox = mbox::RegisterBlock::mbox_csr();
        match mbox.status().read().mbox_fsm_ps() {
            MboxFsmE::MboxExecuteUc => Some(MailboxRecvTxn::default()),
            _ => {
                // Mailbox is locked
                None
            }
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
        let mbox = mbox::RegisterBlock::mbox_csr();
        if mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // SoC firmware might be stuck waiting for Caliptra to finish
            // executing this pending mailbox transaction. Notify them that
            // we've failed.
            mbox.status().write(|w| w.status(|w| w.cmd_failure()));
        }
    }
}

/// MailboxSendTxn protocol abstraction using typestate pattern.
pub struct MailboxSendTxn<S> {
    pub state: S,
}
impl Default for MailboxSendTxn<RdyForCmd> {
    fn default() -> Self {
        MailboxSendTxn { state: RdyForCmd }
    }
}

impl MailboxSendTxn<RdyForCmd> {
    pub fn write_cmd(self, cmd: u32) -> MailboxSendTxn<RdyForDlen> {
        let mbox = mbox::RegisterBlock::mbox_csr();

        // Write Command :
        mbox.cmd().write(|_| cmd);
        MailboxSendTxn { state: RdyForDlen }
    }
}

impl MailboxSendTxn<RdyForDlen> {
    /// Transition to the RdyForData state.
    pub fn try_write_dlen(self, dlen: u32) -> CaliptraResult<MailboxSendTxn<RdyForData>> {
        if dlen > MAX_MAILBOX_LEN {
            raise_err!(InvalidDlenErr);
        }

        let mbox = mbox::RegisterBlock::mbox_csr();

        // Write Data Length :
        mbox.dlen().write(|_| dlen);
        Ok(MailboxSendTxn { state: RdyForData })
    }
}
impl MailboxSendTxn<RdyForData> {
    pub fn try_write_data(self, buf: &[u8]) -> CaliptraResult<MailboxSendTxn<RdyForData>> {
        let remainder = buf.len() % size_of::<u32>();
        let n = buf.len() - remainder;

        let mbox = mbox::RegisterBlock::mbox_csr();

        for idx in (0..n).step_by(size_of::<u32>()) {
            let bytes = buf
                .get(idx..idx + size_of::<u32>())
                .ok_or(err_u32!(EnqueueErr))?;
            mbox.datain()
                .write(|_| u32::from_le_bytes(bytes.try_into().unwrap()));
        }

        // Handle the remainder.
        if remainder > 0 {
            let mut block_part = *buf.get(n).ok_or(err_u32!(EnqueueErr))? as u32;
            for idx in 1..remainder {
                block_part |= (*buf.get(n + idx).ok_or(err_u32!(EnqueueErr))? as u32) << (idx << 3);
            }
            mbox.datain().write(|_| block_part);
        }

        Ok(MailboxSendTxn { state: RdyForData })
    }
    /// Transition to the Execute state.
    pub fn execute(self) -> MailboxSendTxn<Execute> {
        let mbox = mbox::RegisterBlock::mbox_csr();
        // Set Execute Bit
        mbox.execute().write(|w| w.execute(true));
        MailboxSendTxn { state: Execute }
    }
}

impl MailboxSendTxn<Execute> {
    /// Transition to the Idle state.
    pub fn complete(self) {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.execute().write(|w| w.execute(false));
    }
}
/// Drop implementation for MailboxRecvTxn
impl<S> Drop for MailboxSendTxn<S> {
    fn drop(&mut self) {
        goto_idle();
    }
}
fn goto_idle() {
    let mbox = mbox::RegisterBlock::mbox_csr();
    if mbox.status().read().mbox_fsm_ps() == MboxFsmE::MboxRdyForCmd {
        if let Ok(txn) = MailboxSendTxn::default().write_cmd(0).try_write_dlen(0_u32) {
            if let Ok(txn) = txn.try_write_data(&[0u8; 0]) {
                txn.execute().complete();
            }
        }
    }
}
// Mailbox receive protocol abstraction using typestate pattern.
#[derive(Default)]
pub struct MailboxRecvTxn {}
/// Default implementation for MailboxRecvTxn<Execute>
impl MailboxRecvTxn {
    /// Returns the value stored in the command register
    pub fn cmd(&self) -> u32 {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.cmd().read()
    }

    /// Returns the value stored in the data length register. This is the total
    /// size of the mailbox data in bytes.
    pub fn dlen(&self) -> u32 {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.dlen().read()
    }

    /// Read data from the mailbox.
    pub fn read_data(&self, buf: &mut [u32]) {
        let mbox = mbox::RegisterBlock::mbox_csr();
        let dlen_bytes = mbox.dlen().read() as usize;
        let dlen_words = (dlen_bytes + 3) / 4;
        let words_to_read = min(buf.len(), dlen_words);
        for dest_word in buf[0..words_to_read].iter_mut() {
            *dest_word = mbox.dataout().read();
        }
    }

    /// Transition from Execute to Idle (releases the mailbox lock).
    pub fn complete(self, success: bool) {
        // Prevent drop() from being called, since we're going to complete the transaction here
        core::mem::forget(self);
        let status = if success {
            MboxStatusE::CmdComplete
        } else {
            MboxStatusE::CmdFailure
        };

        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.status().write(|w| w.status(|_| status));
    }
}

/// Drop implementation for MailboxRecvTxn
impl Drop for MailboxRecvTxn {
    fn drop(&mut self) {
        let mbox = mbox::RegisterBlock::mbox_csr();

        if mbox.status().read().mbox_fsm_ps() == MboxFsmE::MboxExecuteUc {
            let mbox = mbox::RegisterBlock::mbox_csr();
            mbox.status()
                .write(|w| w.status(|_| MboxStatusE::CmdFailure));
        }
    }
}
