/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/

mod asym_ecc384;
mod doe;
mod emu_ctrl;
mod hash_sha256;
mod hash_sha512;
mod hmac_sha384;
mod key_vault;
mod root_bus;
mod soc_reg;
mod uart;

pub use asym_ecc384::AsymEcc384;
pub use doe::Doe;
pub use emu_ctrl::EmuCtrl;
pub use hash_sha256::HashSha256;
pub use hash_sha512::HashSha512;
pub use hmac_sha384::HmacSha384;
pub use key_vault::KeyVault;
pub use root_bus::CaliptraRootBus;
pub use soc_reg::SocRegisters;
pub use uart::Uart;
