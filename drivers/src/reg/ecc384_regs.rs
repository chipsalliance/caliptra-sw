/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_regs.rs

Abstract:

    File contains register definitions for Elliptic Curve Cryptography P-384 Engine

--*/

use crate::reg::static_ref::StaticRef;
use tock_registers::registers::{ReadOnly, ReadWrite};
use tock_registers::{register_bitfields, register_structs};

register_structs! {
    /// ECC384 Engine Registers
    pub(crate) Ecc384Registers {
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

        /// Side channel protection config
        (0x020 => pub(crate) sca_config: ReadWrite<u32>),

        (0x024 => _reserved2),

        /// Seed for deterministic ECC key generation
        (0x080 => pub(crate) seed: [ReadWrite<u32>; 12]),

        (0x0B0 => _reserved3),

        /// Digest to sign
        (0x100 => pub(crate) digest: [ReadWrite<u32>; 12]),

        (0x130 => _reserved4),

        /// Private Key to use for signing operations
        (0x180 => pub(crate) priv_key: [ReadWrite<u32>; 12]),

        (0x1B0 => _reserved5),

        /// Public Key X-coordinate
        (0x200 => pub(crate) pub_key_x: [ReadWrite<u32>; 12]),

        (0x230 => _reserved6),

        /// Public Key y-coordinate
        (0x280 => pub(crate) pub_key_y: [ReadWrite<u32>; 12]),

        (0x2B0 => _reserved7),

        /// Signature r-coordinate
        (0x300 => pub(crate) sig_r: [ReadWrite<u32>; 12]),

        (0x330 => _reserved8),

        /// Signature s-coordinate
        (0x380 => pub(crate) sig_s: [ReadWrite<u32>; 12]),

        (0x3B0 => _reserved9),

        /// Verify r-coordinate
        (0x400 => pub(crate) verify_r: [ReadOnly<u32>; 12]),

        (0x430 => _reserved10),

        /// Initialization vector used for blinding
        (0x480 => pub(crate) iv: [ReadWrite<u32>; 12]),

        (0x4B0 => _reserved11),

        (0x4B0 => @END),
    }
}

register_bitfields! [
    u32,

    /// Control Register Fields
    pub(crate) CONTROL [
        CMD OFFSET(0) NUMBITS(2) [
            IDLE = 0b00,
            GEN_KEY = 0b01,
            SIGN = 0b10,
            VERIFY = 0b11,
        ],
    ],

    /// Status Register Fields
    pub(crate) STATUS[
        READY OFFSET(0) NUMBITS(1) [],
        VALID OFFSET(1) NUMBITS(1) [],
    ],
];

/// ECC 384 Registers
pub(crate) const ECC384_REGS: StaticRef<Ecc384Registers> =
    unsafe { StaticRef::new(0x1000_8000 as *const Ecc384Registers) };
