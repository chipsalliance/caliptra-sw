/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains API for Mailbox operations

--*/

//use crate::reg::mailbox_regs::*;
use crate::{caliptra_err_def, CaliptraResult};
use caliptra_registers::mbox::{self, enums::MboxStatusE};
use core::mem;
//use tock_registers::interfaces::{Readable, Writeable};

#[derive(PartialEq)]
pub enum Status {
    Busy = 0,
    DataReady = 0x1,
    CmdComplete = 0x2,
    CmdFailure = 0x3,
}

caliptra_err_def! {
    Mailbox,
    MailboxErr
    {
        // Data Exceed max size
        MaxDataErr = 0x1,

    }
}

const MAX_MAILBOX_LEN: usize = 128 * 1024;

pub enum Mailbox {}

impl Mailbox {
    /// Send Data to SOC
    /// * 'cmd' - Command to Be Sent
    /// * 'data' - Data Bufer
    /// # Returns
    ///
    /// * Lock Status
    pub fn send(cmd: u32, data: &[u32]) -> CaliptraResult<bool> {
        // Check Max Len
        if (data.len() * mem::size_of::<u32>()) > MAX_MAILBOX_LEN {
            raise_err!(MaxDataErr)
        }

        let mbox = mbox::RegisterBlock::mbox_csr();

        // if Locked return an error
        if mbox.lock().read().lock() {
            return Ok(false);
        }

        // Write Command
        mbox.cmd().write(|_| cmd);

        // Write Len in Bytes
        mbox.dlen()
            .write(|_| (data.len() * mem::size_of::<u32>()) as u32);

        // Write Data
        for word in data {
            mbox.datain().write(|_| *word);
        }
        // Write Status
        mbox.status().write(|w| w.status(|w| w.data_ready()));

        // Set Execute Bit
        mbox.execute().write(|w| w.execute(true));

        Ok(true)
    }

    /// Read Status Register
    /// # Returns
    ///
    /// * Status Register
    fn status() -> Status {
        let mbox = mbox::RegisterBlock::mbox_csr();
        match mbox.status().read().status() {
            MboxStatusE::CmdBusy => Status::Busy,
            MboxStatusE::DataReady => Status::DataReady,
            MboxStatusE::CmdComplete => Status::CmdComplete,
            MboxStatusE::CmdFailure => Status::CmdFailure,
        }
    }

    /// Read Data Len in Mailbox
    /// # Returns
    ///
    /// * Data Len in Bytes
    pub fn get_data_len() -> u32 {
        let mbox = mbox::RegisterBlock::mbox_csr();
        mbox.dlen().read()
    }

    /// Receive data from SOC
    ///
    /// # Arguments
    ///
    /// * `buffer` - Data to used to update the digest
    /// * 'handler' - Process Handler
    ///
    /// # Returns
    ///
    /// Status of Operation
    ///
    pub fn recv(
        buffer: &mut [u32],
        mut handler: impl FnMut(u32, &mut [u32]) -> bool,
    ) -> CaliptraResult<bool> {
        // Check if Data Ready
        if Mailbox::status() != Status::DataReady {
            return Ok(false);
        }

        let mbox = mbox::RegisterBlock::mbox_csr();
        // Set Status Busy
        mbox.status().write(|w| w.status(|w| w.cmd_busy()));

        // Read len
        let dlen = mbox.dlen().read();
        if dlen > (buffer.len() * mem::size_of::<u32>()) as u32 {
            raise_err!(MaxDataErr);
        }

        // Read Command
        let cmd = mbox.cmd().read();

        // Read Data
        // Todo: Shall this logic go to slice ?
        for word in buffer.iter_mut() {
            *word = mbox.dataout().read();
        }

        // Call Handler
        let rc = handler(cmd, buffer);
        match rc {
            // Set Status Busy
            true => mbox.status().write(|w| w.status(|w| w.cmd_complete())),
            false => mbox.status().write(|w| w.status(|w| w.cmd_failure())),
        }

        // ReSet Execute Bit
        mbox.execute().write(|w| w.execute(false));

        Ok(rc)
    }
}
