/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox.rs

Abstract:

    File contains API for Mailbox operations

--*/

use crate::reg::mailbox_regs::*;
use crate::{cptr_err_def, CptrResult};
use core::mem::size_of;
use tock_registers::interfaces::{Readable, Writeable};

#[derive(PartialEq)]
pub enum Status {
    Busy = 0,
    DataReady = 0x1,
    CmdComplete = 0x2,
    CmdFailure = 0x3,
}

cptr_err_def! {
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
    pub fn send(cmd: u32, data: &[u32]) -> CptrResult<bool> {
        // Check Max Len
        if (data.len() * size_of::<u32>()) > MAX_MAILBOX_LEN {
            raise_err!(MaxDataErr)
        }

        // if Locked return an error
        if MAILBOX_REGS.lock.get() == 1 {
            return Ok(false);
        }

        // Write Command
        MAILBOX_REGS.command.set(cmd);

        // Write Len in Bytes
        MAILBOX_REGS
            .dlen
            .set((data.len() * size_of::<u32>()) as u32);

        // Write Data
        for i in 0..data.len() {
            MAILBOX_REGS.din.set(data[i]);
        }

        // Write Status
        MAILBOX_REGS.status.write(STATUS::STATE::DATA_READY);

        // Set Execute Bit
        MAILBOX_REGS.execute.set(1);

        Ok(true)
    }

    /// Read Status Register
    /// # Returns
    ///
    /// * Status Register
    fn status() -> Status {
        match MAILBOX_REGS.status.read(STATUS::STATE) {
            0x0 => Status::Busy,
            0x1 => Status::DataReady,
            0x2 => Status::CmdComplete,
            0x3 => Status::CmdFailure,
            4_u32..=u32::MAX => todo!(),
        }
    }

    /// Read Data Len in Mailbox
    /// # Returns
    ///
    /// * Data Len in Bytes
    pub fn get_data_len() -> u32 {
        MAILBOX_REGS.dlen.get()
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
    ) -> CptrResult<bool> {
        // Check if Data Ready
        if Mailbox::status() != Status::DataReady {
            return Ok(false);
        }

        // Set Status Busy
        MAILBOX_REGS.status.write(STATUS::STATE::BUSY);

        // Read len
        let dlen = MAILBOX_REGS.dlen.get();
        if dlen > (buffer.len() * size_of::<u32>()) as u32 {
            raise_err!(MaxDataErr);
        }

        // Read Command
        let cmd = MAILBOX_REGS.command.get();

        // Read Data
        // Todo: Shall this logic go to slice ?
        for i in 0..buffer.len() {
            buffer[i] = MAILBOX_REGS.dout.get();
        }

        // Call Handler
        let rc = handler(cmd, buffer);
        match rc == true {
            // Set Status Busy
            true => MAILBOX_REGS.status.write(STATUS::STATE::CMD_COMPLETE),
            false => MAILBOX_REGS.status.write(STATUS::STATE::CMD_FAILURE),
        }

        // ReSet Execute Bit
        MAILBOX_REGS.execute.set(0);

        Ok(rc)
    }
}
