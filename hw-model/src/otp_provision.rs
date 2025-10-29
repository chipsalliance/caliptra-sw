// Licensed under the Apache-2.0 license

#![allow(dead_code)]

use crate::otp_digest::{otp_digest, otp_scramble, otp_unscramble};
use caliptra_image_fake_keys::{VENDOR_ECC_KEY_0_PUBLIC, VENDOR_MLDSA_KEY_0_PUBLIC};

use anyhow::{bail, Result};
use sha2::{Digest, Sha384, Sha512};
use sha3::{digest::ExtendableOutput, digest::Update, CShake128, CShake128Core};
use zerocopy::{FromBytes, IntoBytes, KnownLayout};

/// Unhashed token, suitable for doing lifecycle transitions.
#[derive(Clone, Copy)]
pub struct LifecycleToken(pub [u8; 16]);

impl From<[u8; 16]> for LifecycleToken {
    fn from(value: [u8; 16]) -> Self {
        LifecycleToken(value)
    }
}

impl From<LifecycleToken> for [u8; 16] {
    fn from(value: LifecycleToken) -> Self {
        value.0
    }
}

/// Raw lifecycle tokens.
pub struct LifecycleRawTokens {
    pub test_unlock: [LifecycleToken; 7],
    pub manuf: LifecycleToken,
    pub manuf_to_prod: LifecycleToken,
    pub prod_to_prod_end: LifecycleToken,
    pub rma: LifecycleToken,
}

/// Hashed token, suitable for burning into OTP.
#[derive(Clone, Copy)]
pub struct LifecycleHashedToken(pub [u8; 16]);

impl From<[u8; 16]> for LifecycleHashedToken {
    fn from(value: [u8; 16]) -> Self {
        LifecycleHashedToken(value)
    }
}

impl From<LifecycleHashedToken> for [u8; 16] {
    fn from(value: LifecycleHashedToken) -> Self {
        value.0
    }
}

/// Hashed lifecycle tokens to be burned into OTP to enable lifecycle transitions.
pub struct LifecycleHashedTokens {
    pub test_unlock: [LifecycleHashedToken; 7],
    pub manuf: LifecycleHashedToken,
    pub manuf_to_prod: LifecycleHashedToken,
    pub prod_to_prod_end: LifecycleHashedToken,
    pub rma: LifecycleHashedToken,
}

/// Raw (unhashed) manuf debug unlock token.
#[derive(Clone, Copy)]
pub struct ManufDebugUnlockToken(pub [u32; 8]);

impl From<[u32; 8]> for ManufDebugUnlockToken {
    fn from(value: [u32; 8]) -> Self {
        ManufDebugUnlockToken(value)
    }
}

impl From<ManufDebugUnlockToken> for [u32; 8] {
    fn from(value: ManufDebugUnlockToken) -> Self {
        value.0
    }
}

impl From<ManufDebugUnlockToken> for [u8; 32] {
    fn from(value: ManufDebugUnlockToken) -> Self {
        let mut dest = [0u8; 32];
        let mut offset = 0;
        for &val in value.0.iter() {
            let bytes = val.to_le_bytes(); // Returns [u8; 4]
            dest[offset..offset + 4].copy_from_slice(&bytes);
            offset += 4;
        }
        dest
    }
}

/// Hashed (SHA512) manuf debug unlock token.
#[derive(Clone, Copy)]
pub struct ManufDebugUnlockHashedToken(pub [u8; 64]);

impl From<[u8; 64]> for ManufDebugUnlockHashedToken {
    fn from(value: [u8; 64]) -> Self {
        ManufDebugUnlockHashedToken(value)
    }
}

impl From<ManufDebugUnlockHashedToken> for [u8; 64] {
    fn from(value: ManufDebugUnlockHashedToken) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleControllerState {
    Raw = 0,
    TestUnlocked0 = 1,
    TestLocked0 = 2,
    TestUnlocked1 = 3,
    TestLocked1 = 4,
    TestUnlocked2 = 5,
    TestLocked2 = 6,
    TestUnlocked3 = 7,
    TestLocked3 = 8,
    TestUnlocked4 = 9,
    TestLocked4 = 10,
    TestUnlocked5 = 11,
    TestLocked5 = 12,
    TestUnlocked6 = 13,
    TestLocked6 = 14,
    TestUnlocked7 = 15,
    Dev = 16,
    Prod = 17,
    ProdEnd = 18,
    Rma = 19,
    Scrap = 20,
}

impl core::fmt::Display for LifecycleControllerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LifecycleControllerState::Raw => write!(f, "raw"),
            LifecycleControllerState::TestUnlocked0 => write!(f, "test_unlocked0"),
            LifecycleControllerState::TestLocked0 => write!(f, "test_locked0"),
            LifecycleControllerState::TestUnlocked1 => write!(f, "test_unlocked1"),
            LifecycleControllerState::TestLocked1 => write!(f, "test_locked1"),
            LifecycleControllerState::TestUnlocked2 => write!(f, "test_unlocked2"),
            LifecycleControllerState::TestLocked2 => write!(f, "test_locked2"),
            LifecycleControllerState::TestUnlocked3 => write!(f, "test_unlocked3"),
            LifecycleControllerState::TestLocked3 => write!(f, "test_locked3"),
            LifecycleControllerState::TestUnlocked4 => write!(f, "test_unlocked4"),
            LifecycleControllerState::TestLocked4 => write!(f, "test_locked4"),
            LifecycleControllerState::TestUnlocked5 => write!(f, "test_unlocked5"),
            LifecycleControllerState::TestLocked5 => write!(f, "test_locked5"),
            LifecycleControllerState::TestUnlocked6 => write!(f, "test_unlocked6"),
            LifecycleControllerState::TestLocked6 => write!(f, "test_locked6"),
            LifecycleControllerState::TestUnlocked7 => write!(f, "test_unlocked7"),
            LifecycleControllerState::Dev => write!(f, "dev"),
            LifecycleControllerState::Prod => write!(f, "prod"),
            LifecycleControllerState::ProdEnd => write!(f, "prod_end"),
            LifecycleControllerState::Rma => write!(f, "rma"),
            LifecycleControllerState::Scrap => write!(f, "scrap"),
        }
    }
}

impl core::str::FromStr for LifecycleControllerState {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(LifecycleControllerState::Raw),
            "test_unlocked0" => Ok(LifecycleControllerState::TestUnlocked0),
            "test_locked0" => Ok(LifecycleControllerState::TestLocked0),
            "test_unlocked1" => Ok(LifecycleControllerState::TestUnlocked1),
            "test_locked1" => Ok(LifecycleControllerState::TestLocked1),
            "test_unlocked2" => Ok(LifecycleControllerState::TestUnlocked2),
            "test_locked2" => Ok(LifecycleControllerState::TestLocked2),
            "test_unlocked3" => Ok(LifecycleControllerState::TestUnlocked3),
            "test_locked3" => Ok(LifecycleControllerState::TestLocked3),
            "test_unlocked4" => Ok(LifecycleControllerState::TestUnlocked4),
            "test_locked4" => Ok(LifecycleControllerState::TestLocked4),
            "test_unlocked5" => Ok(LifecycleControllerState::TestUnlocked5),
            "test_locked5" => Ok(LifecycleControllerState::TestLocked5),
            "test_unlocked6" => Ok(LifecycleControllerState::TestUnlocked6),
            "test_locked6" => Ok(LifecycleControllerState::TestLocked6),
            "test_unlocked7" => Ok(LifecycleControllerState::TestUnlocked7),
            "dev" | "manuf" | "manufacturing" => Ok(LifecycleControllerState::Dev),
            "production" | "prod" => Ok(LifecycleControllerState::Prod),
            "prod_end" => Ok(LifecycleControllerState::ProdEnd),
            "rma" => Ok(LifecycleControllerState::Rma),
            "scrap" => Ok(LifecycleControllerState::Scrap),
            _ => Err("Invalid lifecycle state"),
        }
    }
}

impl From<LifecycleControllerState> for u8 {
    fn from(value: LifecycleControllerState) -> Self {
        match value {
            LifecycleControllerState::Raw => 0,
            LifecycleControllerState::TestUnlocked0 => 1,
            LifecycleControllerState::TestLocked0 => 2,
            LifecycleControllerState::TestUnlocked1 => 3,
            LifecycleControllerState::TestLocked1 => 4,
            LifecycleControllerState::TestUnlocked2 => 5,
            LifecycleControllerState::TestLocked2 => 6,
            LifecycleControllerState::TestUnlocked3 => 7,
            LifecycleControllerState::TestLocked3 => 8,
            LifecycleControllerState::TestUnlocked4 => 9,
            LifecycleControllerState::TestLocked4 => 10,
            LifecycleControllerState::TestUnlocked5 => 11,
            LifecycleControllerState::TestLocked5 => 12,
            LifecycleControllerState::TestUnlocked6 => 13,
            LifecycleControllerState::TestLocked6 => 14,
            LifecycleControllerState::TestUnlocked7 => 15,
            LifecycleControllerState::Dev => 16,
            LifecycleControllerState::Prod => 17,
            LifecycleControllerState::ProdEnd => 18,
            LifecycleControllerState::Rma => 19,
            LifecycleControllerState::Scrap => 20,
        }
    }
}

impl From<u8> for LifecycleControllerState {
    fn from(value: u8) -> Self {
        match value {
            1 => LifecycleControllerState::TestUnlocked0,
            2 => LifecycleControllerState::TestLocked0,
            3 => LifecycleControllerState::TestUnlocked1,
            4 => LifecycleControllerState::TestLocked1,
            5 => LifecycleControllerState::TestUnlocked2,
            6 => LifecycleControllerState::TestLocked2,
            7 => LifecycleControllerState::TestUnlocked3,
            8 => LifecycleControllerState::TestLocked3,
            9 => LifecycleControllerState::TestUnlocked4,
            10 => LifecycleControllerState::TestLocked4,
            11 => LifecycleControllerState::TestUnlocked5,
            12 => LifecycleControllerState::TestLocked5,
            13 => LifecycleControllerState::TestUnlocked6,
            14 => LifecycleControllerState::TestLocked6,
            15 => LifecycleControllerState::TestUnlocked7,
            16 => LifecycleControllerState::Dev,
            17 => LifecycleControllerState::Prod,
            18 => LifecycleControllerState::ProdEnd,
            19 => LifecycleControllerState::Rma,
            20 => LifecycleControllerState::Scrap,
            _ => LifecycleControllerState::Raw,
        }
    }
}

impl From<u32> for LifecycleControllerState {
    fn from(value: u32) -> Self {
        ((value & 0x1f) as u8).into()
    }
}

// These are the default lifecycle controller constants from the
// standard Caliptra RTL. These can be overridden by vendors.

// from caliptra-rtl/src/lc_ctrl/rtl/lc_ctrl_state_pkg.sv
const _A0: u16 = 0b0110010010101110; // ECC: 6'b001010
const B0: u16 = 0b0111010111101110; // ECC: 6'b111110
const A1: u16 = 0b0000011110110100; // ECC: 6'b100101
const B1: u16 = 0b0000111111111110; // ECC: 6'b111101
const A2: u16 = 0b0011000111010010; // ECC: 6'b000111
const B2: u16 = 0b0111101111111110; // ECC: 6'b000111
const A3: u16 = 0b0010111001001101; // ECC: 6'b001010
const B3: u16 = 0b0011111101101111; // ECC: 6'b111010
const A4: u16 = 0b0100000111111000; // ECC: 6'b011010
const B4: u16 = 0b0101111111111100; // ECC: 6'b011110
const A5: u16 = 0b1010110010000101; // ECC: 6'b110001
const B5: u16 = 0b1111110110011111; // ECC: 6'b110001
const A6: u16 = 0b1001100110001100; // ECC: 6'b010110
const B6: u16 = 0b1111100110011111; // ECC: 6'b011110
const A7: u16 = 0b0101001100001111; // ECC: 6'b100010
const B7: u16 = 0b1101101101101111; // ECC: 6'b100111
const A8: u16 = 0b0111000101100000; // ECC: 6'b111001
const B8: u16 = 0b0111001101111111; // ECC: 6'b111001
const A9: u16 = 0b0010110001100011; // ECC: 6'b101010
const B9: u16 = 0b0110110001101111; // ECC: 6'b111111
const A10: u16 = 0b0110110100001000; // ECC: 6'b110011
const B10: u16 = 0b0110111110011110; // ECC: 6'b111011
const A11: u16 = 0b1001001001001100; // ECC: 6'b000011
const B11: u16 = 0b1101001111011100; // ECC: 6'b111111
const A12: u16 = 0b0111000001000000; // ECC: 6'b011110
const B12: u16 = 0b0111011101010010; // ECC: 6'b111110
const A13: u16 = 0b1001001010111110; // ECC: 6'b000010
const B13: u16 = 0b1111001011111110; // ECC: 6'b101110
const A14: u16 = 0b1001010011010010; // ECC: 6'b100011
const B14: u16 = 0b1011110111010011; // ECC: 6'b101111
const A15: u16 = 0b0110001010001101; // ECC: 6'b000111
const B15: u16 = 0b0110111111001101; // ECC: 6'b011111
const A16: u16 = 0b1011001000101000; // ECC: 6'b010111
const B16: u16 = 0b1011001011111011; // ECC: 6'b011111
const A17: u16 = 0b0001111001110001; // ECC: 6'b001001
const B17: u16 = 0b1001111111110101; // ECC: 6'b011011
const A18: u16 = 0b0010110110011011; // ECC: 6'b000100
const B18: u16 = 0b0011111111011111; // ECC: 6'b010101
const A19: u16 = 0b0100110110001100; // ECC: 6'b101010
const B19: u16 = 0b1101110110111110; // ECC: 6'b101011

// The C/D values are used for the encoded LC transition counter.

const _C0: u16 = 0b0001010010011110; // ECC: 6'b011100
const D0: u16 = 0b1011011011011111; // ECC: 6'b111100
const C1: u16 = 0b0101101011000100; // ECC: 6'b111000
const D1: u16 = 0b1111101011110100; // ECC: 6'b111101
const C2: u16 = 0b0001111100100100; // ECC: 6'b100011
const D2: u16 = 0b0001111110111111; // ECC: 6'b100111
const C3: u16 = 0b1100111010000101; // ECC: 6'b011000
const D3: u16 = 0b1100111011101111; // ECC: 6'b011011
const C4: u16 = 0b0100001010011111; // ECC: 6'b011000
const D4: u16 = 0b0101101110111111; // ECC: 6'b111100
const C5: u16 = 0b1001111000100010; // ECC: 6'b111000
const D5: u16 = 0b1111111110100010; // ECC: 6'b111110
const C6: u16 = 0b0010011110000110; // ECC: 6'b010000
const D6: u16 = 0b0111011111000110; // ECC: 6'b011101
const C7: u16 = 0b0010111101000110; // ECC: 6'b000110
const D7: u16 = 0b1010111111000110; // ECC: 6'b111111
const C8: u16 = 0b0000001011011011; // ECC: 6'b000001
const D8: u16 = 0b1010101111011011; // ECC: 6'b111011
const C9: u16 = 0b0111000011000110; // ECC: 6'b110001
const D9: u16 = 0b1111111011001110; // ECC: 6'b110011
const C10: u16 = 0b0100001000010010; // ECC: 6'b110110
const D10: u16 = 0b0111001010110110; // ECC: 6'b110111
const C11: u16 = 0b0100101111110001; // ECC: 6'b000001
const D11: u16 = 0b0110101111110011; // ECC: 6'b110111
const C12: u16 = 0b1000100101000001; // ECC: 6'b000001
const D12: u16 = 0b1011110101001111; // ECC: 6'b001011
const C13: u16 = 0b1000000000010001; // ECC: 6'b011111
const D13: u16 = 0b1001100010110011; // ECC: 6'b111111
const C14: u16 = 0b0101110000000100; // ECC: 6'b111110
const D14: u16 = 0b1111111010001101; // ECC: 6'b111110
const C15: u16 = 0b1100001000001001; // ECC: 6'b001011
const D15: u16 = 0b1110011000011011; // ECC: 6'b111011
const C16: u16 = 0b0101001001101100; // ECC: 6'b001000
const D16: u16 = 0b0111111001111110; // ECC: 6'b001001
const C17: u16 = 0b0100001001110100; // ECC: 6'b010100
const D17: u16 = 0b1100101001110111; // ECC: 6'b110110
const C18: u16 = 0b1100000001100111; // ECC: 6'b100000
const D18: u16 = 0b1100011101110111; // ECC: 6'b100101
const C19: u16 = 0b1010000001001010; // ECC: 6'b101111
const D19: u16 = 0b1111011101101010; // ECC: 6'b101111
const C20: u16 = 0b1001001001010101; // ECC: 6'b001110
const D20: u16 = 0b1101111011011101; // ECC: 6'b001111
const C21: u16 = 0b1001010000011011; // ECC: 6'b100000
const D21: u16 = 0b1001111000111011; // ECC: 6'b110101
const C22: u16 = 0b1011101101100001; // ECC: 6'b000100
const D22: u16 = 0b1011111101111111; // ECC: 6'b000110
const C23: u16 = 0b1101101000000111; // ECC: 6'b001100
const D23: u16 = 0b1101111011100111; // ECC: 6'b101110
const ZRO: u16 = 0b0000000000000000; // ECC: 6'b000000

const COUNTS: [[u16; 24]; 25] = [
    [
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, C2, C1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, C2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, C3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        C4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, C5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, C6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, C7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, C8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, C9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, C10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, C11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, C12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, C13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, C14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, C15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, C16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, C17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, C18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, C19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, C20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, C21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, C22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        C23, D22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
    [
        D23, D22, D21, D20, D19, D18, D17, D16, D15, D14, D13, D12, D11, D10, D9, D8, D7, D6, D5,
        D4, D3, D2, D1, D0,
    ],
];

const STATES: [[u16; 20]; 21] = [
    [
        ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO, ZRO,
        ZRO, ZRO,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, A2, A1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, A2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, A3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, A4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, A5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, A6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, A7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, A8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, A9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, A10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, A11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, A12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, A13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, A14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, A15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, A16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, A17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, A18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        A19, B18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
    [
        B19, B18, B17, B16, B15, B14, B13, B12, B11, B10, B9, B8, B7, B6, B5, B4, B3, B2, B1, B0,
    ],
];

pub const LIFECYCLE_STATE_SIZE: usize = 40;
pub const LIFECYCLE_COUNT_SIZE: usize = 48;
pub const LIFECYCLE_MEM_SIZE: usize = LIFECYCLE_STATE_SIZE + LIFECYCLE_COUNT_SIZE;

/// Generate the OTP memory contents associated with the lifecycle state.
pub fn lc_generate_state_mem(
    state: LifecycleControllerState,
) -> Result<[u8; LIFECYCLE_STATE_SIZE]> {
    let state = u8::from(state);
    if state >= STATES.len() as u8 {
        bail!("Invalid lifecycle state: {:?}", state);
    }
    let mut result = [0u8; 40];
    let state_data = STATES[state as usize];
    for (i, &value) in state_data.iter().enumerate() {
        result[i * 2] = (value >> 8) as u8;
        result[i * 2 + 1] = (value & 0xFF) as u8;
    }
    Ok(result)
}

/// Generate the OTP memory contents associated with the lifecycle transition count.
pub fn lc_generate_count_mem(count: u8) -> Result<[u8; LIFECYCLE_COUNT_SIZE]> {
    if count >= COUNTS.len() as u8 {
        bail!("Invalid lifecycle count: {:?}", count);
    }
    let mut result = [0u8; 48];
    let count_data = COUNTS[count as usize];
    for (i, &value) in count_data.iter().enumerate() {
        result[i * 2] = (value >> 8) as u8;
        result[i * 2 + 1] = (value & 0xFF) as u8;
    }
    Ok(result)
}

/// Generate the OTP memory contents associated with the lifecycle state and transition count.
pub fn lc_generate_memory(
    state: LifecycleControllerState,
    transition_count: u8,
) -> Result<[u8; LIFECYCLE_MEM_SIZE]> {
    let mut result = [0u8; LIFECYCLE_MEM_SIZE];
    let state = lc_generate_state_mem(state)?;
    result[..state.len()].copy_from_slice(&state);
    let count = lc_generate_count_mem(transition_count)?;
    result[state.len()..state.len() + count.len()].copy_from_slice(&count);
    result.reverse();

    Ok(result)
}

/// Hash a token using cSHAKE128 for the lifecycle controller.
fn hash_token(raw_token: &[u8; 16]) -> [u8; 16] {
    let mut hasher: CShake128 = CShake128::from_core(CShake128Core::new(b"LC_CTRL"));
    hasher.update(raw_token);
    let mut output = [0u8; 16];
    hasher.finalize_xof_into(&mut output);
    output
}

fn hash_manuf_debug_token(raw_token: &[u8; 32]) -> [u8; 64] {
    let mut hasher: Sha512 = Sha512::new();
    sha2::Digest::update(&mut hasher, raw_token);
    let output: [u8; 64] = hasher.finalize().into();
    output
}

pub const DIGEST_SIZE: usize = 8;

// TODO(timothytrippel): autogenerate these from the OTP memory map definition
// OTP partition sizes.
// Partition sizes are in bytes and include the digest and zeroization fields.
const OTP_SECRET_LC_TRANSITION_PARTITION_SIZE: usize = 184;
const OTP_SW_TEST_UNLOCK_PARTITION_SIZE: usize = 72;
const OTP_SW_MANUF_PARTITION_SIZE: usize = 520;

// Default from caliptra-ss/src/fuse_ctrl/rtl/otp_ctrl_part_pkg.sv
const OTP_IV: u64 = 0x90C7F21F6224F027;
const OTP_CNST: u128 = 0xF98C48B1F93772844A22D4B78FE0266F;

// These are in reverse order from the RTL.
pub(crate) const OTP_SCRAMBLE_KEYS: [u128; 7] = [
    0x3BA121C5E097DDEB7768B4C666E9C3DA,
    0xEFFA6D736C5EFF49AE7B70F9C46E5A62,
    0x85A9E830BC059BA9286D6E2856A05CC3,
    0xBEAD91D5FA4E09150E95F517CB98955B,
    0x4D5A89AA9109294AE048B657396B4B83,
    0x277195FC471E4B26B6641214B61D1B43,
    0xB7474D640F8A7F5D60822E1FAEC5C72,
];

const LC_TOKENS_KEY_IDX: usize = 6;

fn otp_scramble_data(data: &mut [u8], key_idx: usize) -> Result<()> {
    if data.len() % 8 != 0 {
        bail!("Data length must be a multiple of 8 bytes for scrambling");
    }
    if key_idx >= OTP_SCRAMBLE_KEYS.len() {
        bail!("Invalid key index for OTP scrambling");
    }
    for chunk in data.chunks_exact_mut(8) {
        let input = u64::from_le_bytes(chunk.try_into().unwrap());
        let output = otp_scramble(input, OTP_SCRAMBLE_KEYS[key_idx]);
        chunk.copy_from_slice(&output.to_le_bytes());
    }
    Ok(())
}

#[allow(unused)]
fn otp_unscramble_data(data: &mut [u8], key_idx: usize) -> Result<()> {
    if data.len() % 8 != 0 {
        bail!("Data length must be a multiple of 8 bytes for scrambling");
    }
    if key_idx >= OTP_SCRAMBLE_KEYS.len() {
        bail!("Invalid key index for OTP scrambling");
    }
    for chunk in data.chunks_exact_mut(8) {
        let input = u64::from_le_bytes(chunk.try_into().unwrap());
        let output = otp_unscramble(input, OTP_SCRAMBLE_KEYS[key_idx]);
        chunk.copy_from_slice(&output.to_le_bytes());
    }
    Ok(())
}

/// Generate the OTP memory contents for lifecycle tokens partition (including the digest).
pub fn otp_generate_lifecycle_tokens_mem(
    tokens: &LifecycleRawTokens,
) -> Result<[u8; OTP_SECRET_LC_TRANSITION_PARTITION_SIZE]> {
    let mut output = [0u8; OTP_SECRET_LC_TRANSITION_PARTITION_SIZE];
    for (i, token) in tokens.test_unlock.iter().enumerate() {
        let hashed_token = hash_token(&token.0);
        output[i * 16..(i + 1) * 16].copy_from_slice(&hashed_token);
    }
    output[7 * 16..8 * 16].copy_from_slice(&hash_token(&tokens.manuf.0));
    output[8 * 16..9 * 16].copy_from_slice(&hash_token(&tokens.manuf_to_prod.0));
    output[9 * 16..10 * 16].copy_from_slice(&hash_token(&tokens.prod_to_prod_end.0));
    output[10 * 16..11 * 16].copy_from_slice(&hash_token(&tokens.rma.0));

    otp_scramble_data(
        &mut output[..OTP_SECRET_LC_TRANSITION_PARTITION_SIZE - DIGEST_SIZE],
        LC_TOKENS_KEY_IDX,
    )?;

    let digest = otp_digest(
        &output[..OTP_SECRET_LC_TRANSITION_PARTITION_SIZE - DIGEST_SIZE],
        OTP_IV,
        OTP_CNST,
    );
    output[OTP_SECRET_LC_TRANSITION_PARTITION_SIZE - DIGEST_SIZE..]
        .copy_from_slice(&digest.to_le_bytes());
    Ok(output)
}

/// Generate the OTP memory contents for the manuf debug unlock token partition (including the digest).
pub fn otp_generate_manuf_debug_unlock_token_mem(
    token: &ManufDebugUnlockToken,
) -> Result<[u8; OTP_SW_TEST_UNLOCK_PARTITION_SIZE]> {
    let mut output = [0u8; OTP_SW_TEST_UNLOCK_PARTITION_SIZE];
    let mut hash = hash_manuf_debug_token(&<[u8; 32]>::from(*token));
    // Reverse the byte order before setting in OTP so the token is read properly by the HW.
    let mut i = 0;
    for chunk in hash.chunks_exact_mut(4) {
        let word = u32::from_be_bytes(chunk.try_into().unwrap());
        output[i..i + 4].copy_from_slice(&word.to_le_bytes());
        i += 4;
    }
    let digest = otp_digest(
        &output[..OTP_SW_TEST_UNLOCK_PARTITION_SIZE - DIGEST_SIZE],
        OTP_IV,
        OTP_CNST,
    );
    output[OTP_SW_TEST_UNLOCK_PARTITION_SIZE - DIGEST_SIZE..]
        .copy_from_slice(&digest.to_le_bytes());
    Ok(output)
}

// TODO(timothytrippel): autogenerate these field sizes from the OTP memory map.
#[derive(Debug, FromBytes, KnownLayout)]
pub struct OtpSwManufPartition {
    pub anti_rollback_disable: u32,
    pub idevid_cert_attr: [u8; 96],
    pub idevid_cert: u32,
    pub hsm_id: u128,
    pub stepping_id: u32,
    pub prod_debug_unlock_pks_0: [u8; 48],
    pub prod_debug_unlock_pks_1: [u8; 48],
    pub prod_debug_unlock_pks_2: [u8; 48],
    pub prod_debug_unlock_pks_3: [u8; 48],
    pub prod_debug_unlock_pks_4: [u8; 48],
    pub prod_debug_unlock_pks_5: [u8; 48],
    pub prod_debug_unlock_pks_6: [u8; 48],
    pub prod_debug_unlock_pks_7: [u8; 48],
}

impl Default for OtpSwManufPartition {
    fn default() -> Self {
        // Compute the SHA2-384 hash of the default ECDSA and ML-DSA public keys.
        let mut ecdsa_pubkey = [0u32; 24];
        ecdsa_pubkey[..12].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.x);
        ecdsa_pubkey[12..].copy_from_slice(&VENDOR_ECC_KEY_0_PUBLIC.y);
        let mut hasher = Sha384::new();
        sha2::Digest::update(&mut hasher, ecdsa_pubkey.as_bytes());
        sha2::Digest::update(&mut hasher, VENDOR_MLDSA_KEY_0_PUBLIC.0.as_bytes());
        // Reverse bytes in each words so it matches the hash the ROM computes.
        let mut default_prod_debug_unlock_pks: [u8; 48] = hasher.finalize().into();
        for chunk in default_prod_debug_unlock_pks.chunks_mut(4) {
            chunk.reverse();
        }
        Self {
            anti_rollback_disable: 0x1,
            idevid_cert_attr: [0; 96],
            idevid_cert: 0,
            hsm_id: 0,
            stepping_id: 0,
            prod_debug_unlock_pks_0: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_1: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_2: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_3: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_4: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_5: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_6: default_prod_debug_unlock_pks,
            prod_debug_unlock_pks_7: default_prod_debug_unlock_pks,
        }
    }
}

/// Generate the OTP memory contents for the SW_MANUF partition, including the digest.
pub fn otp_generate_sw_manuf_partition_mem(
    sw_manuf_partition: &OtpSwManufPartition,
) -> Result<[u8; OTP_SW_MANUF_PARTITION_SIZE]> {
    let mut output = [0u8; OTP_SW_MANUF_PARTITION_SIZE];
    let mut offset = 0;
    let out = &mut output;
    let off = &mut offset;

    fn push(out_buf: &mut [u8], out_offset: &mut usize, src_buf: &[u8]) {
        let len = src_buf.len();
        out_buf[*out_offset..*out_offset + len].copy_from_slice(src_buf);
        *out_offset += len;
    }

    // Anti-Rollback Disable field.
    push(
        out,
        off,
        &sw_manuf_partition.anti_rollback_disable.to_le_bytes(),
    );

    // IDevID Cert Attributes field.
    push(out, off, &sw_manuf_partition.idevid_cert_attr);
    // IDevID Cert field.
    push(out, off, &sw_manuf_partition.idevid_cert.to_le_bytes());
    // HSM ID field.
    push(out, off, &sw_manuf_partition.hsm_id.to_le_bytes());
    // Stepping ID field.
    push(out, off, &sw_manuf_partition.stepping_id.to_le_bytes());

    // Prod debug unlock public key hash fields.
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_0);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_1);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_2);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_3);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_4);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_5);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_6);
    push(out, off, &sw_manuf_partition.prod_debug_unlock_pks_7);

    // Compute and write digest field to lock the partition.
    let digest = otp_digest(
        &output[..OTP_SW_MANUF_PARTITION_SIZE - DIGEST_SIZE],
        OTP_IV,
        OTP_CNST,
    );
    output[OTP_SW_MANUF_PARTITION_SIZE - DIGEST_SIZE..].copy_from_slice(&digest.to_le_bytes());

    Ok(output)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_otp_unscramble_token() {
        let raw_token = LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());
        let tokens = LifecycleRawTokens {
            test_unlock: [raw_token; 7],
            manuf: raw_token,
            manuf_to_prod: raw_token,
            prod_to_prod_end: raw_token,
            rma: raw_token,
        };
        let mut memory = otp_generate_lifecycle_tokens_mem(&tokens).unwrap();
        otp_unscramble_data(&mut memory[..16], LC_TOKENS_KEY_IDX).unwrap();
        let expected_hashed_token: [u8; 16] = 0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes();
        assert_eq!(&memory[..16], &expected_hashed_token);
    }

    #[test]
    fn test_otp_generate_lifecycle_tokens_mem() {
        let raw_token = LifecycleToken(0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes());
        let tokens = LifecycleRawTokens {
            test_unlock: [raw_token; 7],
            manuf: raw_token,
            manuf_to_prod: raw_token,
            prod_to_prod_end: raw_token,
            rma: raw_token,
        };
        let memory = otp_generate_lifecycle_tokens_mem(&tokens).unwrap();

        let expected: [u8; 184] = [
            0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c,
            0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1,
            0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27,
            0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae,
            0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b,
            0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c,
            0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84,
            0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd,
            0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c,
            0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27, 0x8d, 0xe1,
            0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae, 0xbc, 0x27,
            0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x16, 0x84, 0x0d, 0x3c, 0x82, 0x1b, 0x86, 0xae,
            0xbc, 0x27, 0x8d, 0xe1, 0xf1, 0x4c, 0x13, 0xbd, 0x79, 0xf0, 0x7f, 0x3a, 0x7b, 0x09,
            0x96, 0xe3,
        ];

        assert_eq!(memory, expected);
    }

    #[test]
    fn test_hash_token() {
        let raw_token: [u8; 16] = 0x05edb8c608fcc830de181732cfd65e57u128.to_le_bytes();
        let expected_hashed_token: [u8; 16] = 0x9c5f6f5060437af930d06d56630a536bu128.to_le_bytes();
        assert_eq!(hash_token(&raw_token), expected_hashed_token);
    }

    #[test]
    fn test_lifecycle_unlocked1() {
        let memory = lc_generate_memory(LifecycleControllerState::TestUnlocked0, 1).unwrap();
        let expected: [u8; LIFECYCLE_MEM_SIZE] = [
            0xdf, 0xb6, 0xc4, 0x5a, 0x24, 0x1f, 0x85, 0xce, 0x9f, 0x42, 0x22, 0x9e, 0x86, 0x27,
            0x46, 0x2f, 0xdb, 0x02, 0xc6, 0x70, 0x12, 0x42, 0xf1, 0x4b, 0x41, 0x89, 0x11, 0x80,
            0x04, 0x5c, 0x09, 0xc2, 0x6c, 0x52, 0x74, 0x42, 0x67, 0xc0, 0x4a, 0xa0, 0x55, 0x92,
            0x1b, 0x94, 0x61, 0xbb, 0x07, 0xda, 0xee, 0x75, 0xb4, 0x07, 0xd2, 0x31, 0x4d, 0x2e,
            0xf8, 0x41, 0x85, 0xac, 0x8c, 0x99, 0x0f, 0x53, 0x60, 0x71, 0x63, 0x2c, 0x08, 0x6d,
            0x4c, 0x92, 0x40, 0x70, 0xbe, 0x92, 0xd2, 0x94, 0x8d, 0x62, 0x28, 0xb2, 0x71, 0x1e,
            0x9b, 0x2d, 0x8c, 0x4d,
        ];
        assert_eq!(memory, expected);
    }

    #[test]
    fn test_lifecycle_manufacturing() {
        let memory = lc_generate_memory(LifecycleControllerState::Dev, 2).unwrap();
        let expected: [u8; LIFECYCLE_MEM_SIZE] = [
            0xdf, 0xb6, 0xf4, 0xfa, 0x24, 0x1f, 0x85, 0xce, 0x9f, 0x42, 0x22, 0x9e, 0x86, 0x27,
            0x46, 0x2f, 0xdb, 0x02, 0xc6, 0x70, 0x12, 0x42, 0xf1, 0x4b, 0x41, 0x89, 0x11, 0x80,
            0x04, 0x5c, 0x09, 0xc2, 0x6c, 0x52, 0x74, 0x42, 0x67, 0xc0, 0x4a, 0xa0, 0x55, 0x92,
            0x1b, 0x94, 0x61, 0xbb, 0x07, 0xda, 0xee, 0x75, 0xfe, 0x0f, 0xfe, 0x7b, 0x6f, 0x3f,
            0xfc, 0x5f, 0x9f, 0xfd, 0x9f, 0xf9, 0x6f, 0xdb, 0x7f, 0x73, 0x6f, 0x6c, 0x9e, 0x6f,
            0xdc, 0xd3, 0x52, 0x77, 0xfe, 0xf2, 0xd3, 0xbd, 0xcd, 0x6f, 0x28, 0xb2, 0x71, 0x1e,
            0x9b, 0x2d, 0x8c, 0x4d,
        ];
        assert_eq!(memory, expected);
    }
}
