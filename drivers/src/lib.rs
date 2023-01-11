/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod reg;

mod error;
mod slice;

mod doe;
mod ecc384;
mod hmac384;
mod key_vault;
mod mailbox;
mod sha256;
mod sha384;


pub type CptrResult<T> = Result<T, u32>;
pub use doe::Doe;
pub use ecc384::{Ecc384, Ecc384PrivKey, Ecc384PubKey, Ecc384Signature};
pub use error::CptrComponent;
pub use hmac384::Hmac384;
pub use key_vault::KeyId;
pub use mailbox::Mailbox;
pub use sha256::Sha256;
pub use sha384::Sha384;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;
        mod emu_ctrl;

        pub use uart::Uart;
        pub use emu_ctrl::EmuCtrl;
    }
}
