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
mod csrng;
mod dma;
mod doe;
mod emu_ctrl;
mod hash_sha256;
mod hash_sha512;
mod helpers;
mod hmac_sha384;
mod iccm;
mod key_vault;
mod mailbox;
mod ml_dsa87;
mod recovery;
mod root_bus;
mod sha512_acc;
pub mod soc_reg;
mod uart;

pub use asym_ecc384::AsymEcc384;
pub use csrng::Csrng;
pub use dma::Dma;
pub use doe::Doe;
pub use emu_ctrl::EmuCtrl;
pub use hash_sha256::HashSha256;
pub use hash_sha512::HashSha512;
pub use hmac_sha384::HmacSha384;
pub use iccm::Iccm;
pub use key_vault::KeyUsage;
pub use key_vault::KeyVault;
pub use mailbox::{MailboxExternal, MailboxInternal, MailboxRam};
pub use root_bus::{
    ActionCb, CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, ReadyForFwCb,
    SocToCaliptraBus, TbServicesCb, UploadUpdateFwCb,
};
pub use sha512_acc::Sha512Accelerator;
pub use soc_reg::SocRegistersInternal;
pub use uart::Uart;
