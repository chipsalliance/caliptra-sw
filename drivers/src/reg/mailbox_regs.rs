/*++

Licensed under the Apache-2.0 license.

File Name:

    mbox_regs.rs

Abstract:

    File contains register definitions for Mailbox Engine

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// Mailbox Engine Registers
    pub(crate) MailboxRegisters {
        /// Lock Register
        (0x000 => pub(crate) lock: ReadOnly<u32>),

        /// User Register
        (0x004 => pub(crate) user: ReadOnly<u32>),

        /// Cmd Register
        (0x008 => pub(crate) command: ReadWrite<u32>),

        /// Dlen Register
        (0x00C => pub(crate) dlen: ReadWrite<u32>),

        /// DataIn Register
        (0x010 => pub(crate) din: WriteOnly<u32>),

        /// DataOut Register
        (0x014 => pub(crate) dout: ReadOnly<u32>),

        /// Execute Register
        (0x018 => pub(crate) execute: WriteOnly<u32>),

        /// Status Register
        (0x01c => pub(crate) status: ReadWrite<u32, STATUS::Register>),

        (0x020 => @END),
    }
}

register_bitfields! [
    u32,

    pub(crate) STATUS [
        STATE OFFSET(0) NUMBITS(2) [
            BUSY = 0b00,
            DATA_READY = 0b01,
            CMD_COMPLETE = 0b10,
            CMD_FAILURE = 0b11,
        ]
    ]
];

pub(crate) const MAILBOX_REGS: StaticRef<MailboxRegisters> =
    unsafe { StaticRef::new(0x3002_0000 as *const MailboxRegisters) };
