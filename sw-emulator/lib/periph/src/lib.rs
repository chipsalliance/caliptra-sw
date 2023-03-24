/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/
#[macro_use]
extern crate arrayref;

mod asym_ecc384;
mod doe;
mod emu_ctrl;
mod hash_sha256;
mod hash_sha512;
mod helpers;
mod hmac_sha384;
mod iccm;
mod key_vault;
mod mailbox;
mod root_bus;
mod sha512_acc;
mod soc_reg;
mod uart;

pub use asym_ecc384::AsymEcc384;
pub use doe::Doe;
pub use emu_ctrl::EmuCtrl;
pub use hash_sha256::HashSha256;
pub use hash_sha512::HashSha512;
pub use hmac_sha384::HmacSha384;
pub use iccm::Iccm;
pub use key_vault::KeyUsage;
pub use key_vault::KeyVault;
pub use mailbox::{Mailbox, MailboxRam};
pub use root_bus::{CaliptraRootBus, CaliptraRootBusArgs, ReadyForFwCb, TbServicesCb};
pub use sha512_acc::Sha512Accelerator;
pub use soc_reg::SocRegisters;
pub use uart::Uart;
