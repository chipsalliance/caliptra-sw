/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Library.

--*/

#![no_std]

mod reg;

mod array;
mod error;
//mod slice;
mod wait;

mod doe;
mod ecc384;
mod hmac384;
mod key_vault;
mod kv_access;
mod mailbox;
mod pcr_bank;
mod sha256;
mod sha384;
mod sha384acc;

pub type CaliptraResult<T> = Result<T, u32>;
pub use array::{Array4x12, Array4x4, Array4x8};
pub use doe::DeobfuscationEngine;
pub use ecc384::{
    Ecc384, Ecc384Data, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Scalar, Ecc384Seed,
    Ecc384Signature,
};
pub use error::CptrComponent;
pub use hmac384::Hmac384;
pub use key_vault::{KeyId, KeyUsage, KeyVault};
pub use kv_access::{KeyReadArgs, KeyWriteArgs};
pub use mailbox::{Mailbox, MailboxSendTxn, MailboxRecvTxn};
pub use pcr_bank::{PcrBank, PcrId};
pub use sha256::Sha256;
pub use sha384::{Sha384, Sha384Data, Sha384Digest};
pub use sha384acc::Sha384Acc;

cfg_if::cfg_if! {
    if #[cfg(feature = "emu")] {
        mod uart;
        mod emu_ctrl;

        pub use uart::Uart;
        pub use emu_ctrl::EmuCtrl;
    }
}
