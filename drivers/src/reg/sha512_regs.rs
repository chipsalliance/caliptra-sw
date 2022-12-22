/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512_regs.rs

Abstract:

    File contains register definitions for SHA-512 Engine

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// SHA512 Engine Registers
    pub(crate) Sha512Registers {
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

        /// SHA-512 Block
        (0x080 => pub(crate) block: [WriteOnly<u32>; 32]),

        /// SHA-512 Digest
        (0x100 => pub(crate) digest: [ReadOnly<u32>; 16]),

        (0x140 => _reserved2),

        (0x608 => _reserved3),

        (0x800 => @END),
    }
}

register_bitfields! [
    u32,

    /// Control Register Fields
    pub(crate) CONTROL [
        INIT OFFSET(0) NUMBITS(1) [],
        NEXT OFFSET(1) NUMBITS(1) [],
        MODE OFFSET(2) NUMBITS(2) [
            SHA512_224 = 0b00,
            SHA512_256 = 0b01,
            SHA384 = 0b10,
            SHA512 = 0b11,
        ],
    ],

    /// Status Register Fields
    pub(crate)  STATUS [
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

pub(crate) const SHA512_REGS: StaticRef<Sha512Registers> =
    unsafe { StaticRef::new(0x1002_0000 as *const Sha512Registers) };
