/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/

mod emu_ctrl;
mod root_bus;
mod uart;

pub use emu_ctrl::EmuCtrl;
pub use root_bus::CaliptraRootBus;
pub use uart::Uart;
