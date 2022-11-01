/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{AsymEcc384, EmuCtrl, HashSha256, HashSha512, HmacSha384, Uart};
use caliptra_emu_bus::{Clock, Ram, Rom};
use caliptra_emu_derive::Bus;

#[derive(Bus)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
    pub rom: Rom,

    #[peripheral(offset = 0x1000_8000, mask = 0x0000_7fff)]
    pub ecc384: AsymEcc384,

    #[peripheral(offset = 0x1001_0000, mask = 0x0000_7fff)]
    pub hmac: HmacSha384,

    #[peripheral(offset = 0x1002_0000, mask = 0x0000_7fff)]
    pub sha512: HashSha512,

    #[peripheral(offset = 0x1002_8000, mask = 0x0000_7fff)]
    pub sha256: HashSha256,

    #[peripheral(offset = 0x4000_0000, mask = 0x0000_ffff)]
    pub iccm: Ram,

    #[peripheral(offset = 0x4004_0000, mask = 0x0000_ffff)]
    pub dccm: Ram,

    #[peripheral(offset = 0x2000_1000, mask = 0x0000_0fff)]
    pub uart: Uart,

    #[peripheral(offset = 0x2000_f000, mask = 0x0000_0fff)]
    pub ctrl: EmuCtrl,
}

impl CaliptraRootBus {
    pub const ROM_SIZE: usize = 32 * 1024;
    pub const ICCM_SIZE: usize = 128 * 1024;
    pub const DCCM_SIZE: usize = 128 * 1024;

    pub fn new(clock: &Clock, rom: Vec<u8>) -> Self {
        Self {
            rom: Rom::new(rom),
            ecc384: AsymEcc384::new(clock),
            hmac: HmacSha384::new(clock),
            sha512: HashSha512::new(clock),
            sha256: HashSha256::new(clock),
            iccm: Ram::new(vec![0; Self::ICCM_SIZE]),
            dccm: Ram::new(vec![0; Self::DCCM_SIZE]),
            uart: Uart::new(),
            ctrl: EmuCtrl::new(),
        }
    }
}
