/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Peripheral library.

--*/
#[macro_use]
extern crate arrayref;

mod aes;
mod aes_clp;
mod asym_ecc384;
mod csrng;
pub mod dma;
mod doe;
mod emu_ctrl;
mod hash_sha256;
mod hash_sha512;
mod helpers;
mod hmac;
mod iccm;
mod key_vault;
mod mailbox;
pub mod mci;
mod ml_dsa87;
mod root_bus;
mod sha512_acc;
pub mod soc_reg;
mod uart;

pub use aes::Aes;
pub use aes_clp::AesClp;
pub use asym_ecc384::AsymEcc384;
pub use csrng::Csrng;
pub use dma::Dma;
pub use doe::Doe;
pub use emu_ctrl::EmuCtrl;
pub use hash_sha256::HashSha256;
pub use hash_sha512::HashSha512;
pub use hmac::HmacSha;
pub use iccm::Iccm;
pub use key_vault::KeyUsage;
pub use key_vault::KeyVault;
pub use mailbox::{MailboxExternal, MailboxInternal, MailboxRam, MailboxRequester};
pub use mci::Mci;
pub use root_bus::{
    ActionCb, CaliptraRootBus, CaliptraRootBusArgs, DownloadIdevidCsrCb, ReadyForFwCb,
    SocToCaliptraBus, TbServicesCb, UploadUpdateFwCb,
};
pub use sha512_acc::Sha512Accelerator;
pub use soc_reg::SocRegistersInternal;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::RwLock;
pub use uart::Uart;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref GLOBAL_OUTPUT: Arc<RwLock<Vec<u8>>> = Arc::new(RwLock::new(Vec::new()));
}

pub struct OutputWriter {}

impl Write for OutputWriter {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut output = GLOBAL_OUTPUT.write().unwrap();
        output.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

pub fn output() -> OutputWriter {
    OutputWriter {}
}
