/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256_regs.rs

Abstract:

    File contains register definitions for SHA-256 Engine

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// SHA256 Engine Registers
    pub(crate) Sha256Registers {
        /// Name 0 Register
        (0x000 => pub(crate) name0: ReadOnly<u32>),

        /// Name 1 Register
        (0x004 => pub(crate) name1: ReadOnly<u32>),

        /// Version 0 Register
        (0x008 => pub(crate) version0: ReadOnly<u32>),

        /// Version 1 Register
        (0x00C => pub(crate) version1: ReadOnly<u32>),

        /// Control Register
        (0x010 => pub(crate) control: ReadWrite<u32, CONTROL::Register>),

        (0x014 => _reserved0),

        /// Status Register
        (0x018 => pub(crate) status: ReadOnly<u32, STATUS::Register>),

        (0x01C => _reserved1),

        /// SHA-256 Block
        (0x080 => pub(crate) block: [WriteOnly<u32>; 16]),

        (0x0C0 => _reserved2),

        /// SHA-256 Digest
        (0x100 => pub(crate) digest: [ReadOnly<u32>; 8]),

        (0x120 => _reserved3),

        (0x800 => @END),
    }
}

register_bitfields! [
    u32,

    /// Control Register Fields
    pub(crate) CONTROL [
        INIT OFFSET(0) NUMBITS(1) [],
        NEXT OFFSET(1) NUMBITS(1) [],
        MODE OFFSET(2) NUMBITS(1) [
            SHA256_224 = 0b00,
            SHA256 = 0b01,
        ],
    ],

    /// Status Register Fields
    pub(crate)  STATUS [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

pub(crate) const SHA256_REGS: StaticRef<Sha256Registers> =
    unsafe { StaticRef::new(0x1002_8000 as *const Sha256Registers) };
