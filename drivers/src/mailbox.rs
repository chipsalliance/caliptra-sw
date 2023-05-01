/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains API for Mailbox operations

--*/

use crate::{caliptra_err_def, CaliptraResult};
use caliptra_registers::mbox::enums::MboxFsmE;
use caliptra_registers::mbox::{self, enums::MboxStatusE};
use core::cmp::min;
use core::mem::size_of;

caliptra_err_def! {
    Mailbox,
    MailboxErr
    {
        // Invalid state
        InvalidStateErr = 0x1,
        // Exceeds mailbox capacity
        InvalidDlenErr = 0x2,
        // No data avaiable.
        NoDataAvailErr = 0x03,
        // Enqueue Error
        EnqueueErr = 0x04,
        // Dequeue Error
        DequeueErr = 0x05,
    }
}

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

#[derive(Default, Debug)]
/// Caliptra mailbox abstraction
pub struct Mailbox {}

const MAX_MAILBOX_LEN: u32 = 128 * 1024;

impl Mailbox {
    /// Attempt to acquire the lock to start sending data.
    /// # Returns
    /// * `MailboxSendTxn` - Object representing a send operation
    pub fn try_start_send_txn(&self) -> Option<MailboxSendTxn> {
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
        let mbox = mbox::RegisterBlock::mbox_csr();
        if mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // SoC firmware might be stuck waiting for Caliptra to finish
            // executing this pending mailbox transaction. Notify them that
            // we've failed.
            mbox.status().write(|w| w.status(|w| w.cmd_failure()));
        }
    }
}

#[derive(Default)]
/// Mailbox send protocol abstraction
pub struct MailboxSendTxn {
    /// Current state.
    state: MailboxOpState,
}

impl MailboxSendTxn {
    ///
    /// Transitions from RdyCmd --> RdyForDlen
    ///
    pub fn write_cmd(&mut self, cmd: u32) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForCmd {
            raise_err!(InvalidStateErr)
        }
        let mbox = mbox::RegisterBlock::mbox_csr();

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
            raise_err!(InvalidStateErr)
        }
        let mbox = mbox::RegisterBlock::mbox_csr();

        if dlen > MAX_MAILBOX_LEN {
            raise_err!(InvalidDlenErr);
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
            raise_err!(InvalidStateErr)
        }

        self.write_cmd(cmd)?;

        self.write_dlen(data.len() as u32)?;

        // Copy data to mailbox
        self.enqueue(data)?;

        self.state = MailboxOpState::RdyForData;

        Ok(())
    }

    fn enqueue(&self, buf: &[u8]) -> CaliptraResult<()> {
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

        Ok(())
    }

    ///
    /// Transitions from RdyForData --> Execute
    ///
    pub fn execute_request(&mut self) -> CaliptraResult<()> {
        if self.state != MailboxOpState::RdyForData {
            raise_err!(InvalidStateErr)
        }

        let mbox = mbox::RegisterBlock::mbox_csr();

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
        let mbox = mbox::RegisterBlock::mbox_csr();

        matches!(
            mbox.status().read().status(),
            MboxStatusE::CmdComplete | MboxStatusE::CmdFailure
        )
    }

    pub fn status(&self) -> MboxStatusE {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.status().read().status()
    }

    ///
    /// Transitions from Execute --> Idle (releases the lock)
    ///
    pub fn complete(&mut self) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            raise_err!(InvalidStateErr)
        }
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.execute().write(|w| w.execute(false));
        self.state = MailboxOpState::Idle;
        Ok(())
    }
}

impl Drop for MailboxSendTxn {
    fn drop(&mut self) {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.unlock().write(|w| w.unlock(true));
    }
}

/// Mailbox recveive protocol abstraction
pub struct MailboxRecvTxn {
    /// Current state of transaction
    state: MailboxOpState,
}

impl Default for MailboxRecvTxn {
    fn default() -> Self {
        Self {
            state: MailboxOpState::Execute,
        }
    }
}

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

    fn dequeue(&self, buf: &mut [u32]) -> CaliptraResult<()> {
        let mbox = mbox::RegisterBlock::mbox_csr();
        let dlen_bytes = mbox.dlen().read() as usize;
        let dlen_words = (dlen_bytes + 3) / 4;
        let words_to_read = min(buf.len(), dlen_words);
        for dest_word in buf[0..words_to_read].iter_mut() {
            *dest_word = mbox.dataout().read();
        }
        Ok(())
    }

    /// Pulls at most `data.len()` words from the mailbox FIFO without performing state transition.
    ///
    /// # Arguments
    ///
    /// * `data` - data buffer.
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///   
    pub fn copy_request(&self, data: &mut [u32]) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            raise_err!(InvalidStateErr)
        }
        self.dequeue(data)
    }

    /// Pulls at most `data.len()` words from the mailbox FIFO.
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
    pub fn recv_request(&mut self, data: &mut [u32]) -> CaliptraResult<()> {
        self.copy_request(data)?;
        self.complete(true)?;
        Ok(())
    }

    ///
    /// Transitions from Execute --> Idle
    ///
    pub fn complete(&mut self, success: bool) -> CaliptraResult<()> {
        if self.state != MailboxOpState::Execute {
            raise_err!(InvalidStateErr)
        }
        let status = if success {
            MboxStatusE::CmdComplete
        } else {
            MboxStatusE::CmdFailure
        };

        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.status().write(|w| w.status(|_| status));

        self.state = MailboxOpState::Idle;
        Ok(())
    }
}

impl Drop for MailboxRecvTxn {
    fn drop(&mut self) {
        if self.state != MailboxOpState::Idle {
            // Execute -> Idle (releases lock)
            let _ = self.complete(false);
        }
    }
}
