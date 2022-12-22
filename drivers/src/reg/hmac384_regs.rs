/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_regs.rs

Abstract:

    File contains register definitions for HMAC384 device control

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::registers::{ReadOnly, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    pub(crate) Hmac384Registers {
        (0x0000_0000 => pub(crate) name0    :   ReadOnly<u32>),
        (0x0000_0004 => pub(crate) name1    :   ReadOnly<u32>),
        (0x0000_0008 => pub(crate) version0 :   ReadOnly<u32>),
        (0x0000_000C => pub(crate) version1 :   ReadOnly<u32>),
        (0x0000_0010 => pub(crate) control  :   WriteOnly<u32, CONTROL::Register>),

        (0x0000_0014 => _reserved),

        (0x0000_0018 => pub(crate) status   :   ReadOnly<u32, STATUS::Register>),

        (0x0000_001C => _reserved1),

        (0x0000_0040 => pub(crate) key     :   [WriteOnly<u32>; 12]),

        (0x0000_0070 => _reserved3),

        (0x0000_0080 => pub(crate) block   :   [WriteOnly<u32>;32]),
        (0x0000_0100 => pub(crate) tag     :   [ReadOnly<u32>;12]),

        (0x0000_0130 => _reserved4),

        (0x0000_0204 => @END),
    }
}

register_bitfields! [
    u32,

    // Name Offset And Number Of Bits
    // The way to define the registers bitfeilds are
    // using the "BitName" OFFSET and Number Of Bits
    // Combination.

    /// Control Register Fields
    pub(crate) CONTROL [

        INIT OFFSET(0) NUMBITS(1) [],
        NEXT OFFSET(1) NUMBITS(1) [],
    ],

    /// Status Register Fields
    pub(crate) STATUS[

        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],

];

pub(crate) const HMAC384_REGS: StaticRef<Hmac384Registers> =
    unsafe { StaticRef::new(0x1001_0000 as *const Hmac384Registers) };
