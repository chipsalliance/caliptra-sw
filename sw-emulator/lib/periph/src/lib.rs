/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/

mod emu_ctrl;
mod hmac_sha384;
mod root_bus;
mod uart;
mod sha512_periph;
mod sha256_periph;

pub use emu_ctrl::EmuCtrl;
pub use hmac_sha384::HmacSha384;
pub use root_bus::CaliptraRootBus;
pub use uart::Uart;
