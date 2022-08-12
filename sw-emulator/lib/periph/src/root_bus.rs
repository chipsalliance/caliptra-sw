/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::EmuCtrl;
use crate::Uart;
use caliptra_emu_bus::{Ram, Rom};
use caliptra_emu_derive::Bus;

#[derive(Bus)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
    pub rom: Rom,

    #[peripheral(offset = 0x4000_0000, mask = 0x0fff_ffff)]
    pub iccm: Ram,

    #[peripheral(offset = 0x5000_0000, mask = 0x0fff_ffff)]
    pub dccm: Ram,

    #[peripheral(offset = 0x2000_0000, mask = 0x0fff_ffff)]
    pub uart: Uart,

    #[peripheral(offset = 0x3000_0000, mask = 0x0fff_ffff)]
    pub ctrl: EmuCtrl,
}

impl CaliptraRootBus {
    pub const ROM_SIZE: usize = 32 * 1024;
    pub const ICCM_SIZE: usize = 128 * 1024;
    pub const DCCM_SIZE: usize = 128 * 1024;

    pub fn new(rom: Vec<u8>) -> Self {
        Self {
            rom: Rom::new(rom),
            iccm: Ram::new(vec![0; Self::ICCM_SIZE]),
            dccm: Ram::new(vec![0; Self::DCCM_SIZE]),
            uart: Uart::new(),
            ctrl: EmuCtrl::new(),
        }
    }
}
