/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for for Caliptra Emulator Crypto library.

--*/

mod aes256cbc;
mod aes256ctr;
mod aes256gcm;
mod ecc384;
mod helpers;
mod hmac512;
mod sha256;
mod sha3;
mod sha512;

pub use sha256::Sha256;
pub use sha256::Sha256Mode;

pub use sha512::Sha512;
pub use sha512::Sha512Mode;

pub use sha3::{Sha3, Sha3Mode, Sha3Strength};

pub use hmac512::{Hmac512, Hmac512Interface, Hmac512Mode};

pub use ecc384::Ecc384;
pub use ecc384::Ecc384PrivKey;
pub use ecc384::Ecc384PubKey;
pub use ecc384::Ecc384Signature;

pub const AES_256_BLOCK_SIZE: usize = 16;
pub const AES_256_KEY_SIZE: usize = 32;
pub use aes256cbc::Aes256Cbc;
pub use aes256ctr::Aes256Ctr;
pub use aes256gcm::{Aes256Gcm, GHash};
pub use helpers::EndianessTransform;
