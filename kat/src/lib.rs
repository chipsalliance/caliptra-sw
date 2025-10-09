/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Caliptra Known Answer Tests.

--*/

#![no_std]

mod aes256cbc_kat;
mod aes256cmac_kat;
mod aes256ctr_kat;
mod aes256ecb_kat;
mod aes256gcm_kat;
mod cmackdf_kat;
mod ecc384_kat;
mod ecdh_kat;
mod hkdf_kat;
mod hmac_kdf_kat;
mod kats_env;
mod lms_kat;
mod mldsa87_kat;
mod sha1_kat;
mod sha256_kat;
mod sha2_512_384acc_kat;
mod sha384_kat;
mod sha3_kat;
mod sha512_kat;

pub use aes256cbc_kat::Aes256CbcKat;
pub use aes256cmac_kat::Aes256CmacKat;
pub use aes256ctr_kat::Aes256CtrKat;
pub use aes256ecb_kat::Aes256EcbKat;
pub use aes256gcm_kat::Aes256GcmKat;
pub use caliptra_drivers::{CaliptraError, CaliptraResult};
pub use cmackdf_kat::CmacKdfKat;
pub use ecc384_kat::Ecc384Kat;
pub use ecdh_kat::EcdhKat;
pub use hkdf_kat::{Hkdf384Kat, Hkdf512Kat};
pub use hmac_kdf_kat::{Hmac384KdfKat, Hmac512KdfKat};
pub use kats_env::KatsEnv;
pub use lms_kat::LmsKat;
pub use mldsa87_kat::Mldsa87Kat;
pub use sha1_kat::Sha1Kat;
pub use sha256_kat::Sha256Kat;
pub use sha2_512_384acc_kat::Sha2_512_384AccKat;
pub use sha384_kat::Sha384Kat;
pub use sha3_kat::Shake256Kat;
pub use sha512_kat::Sha512Kat;

use caliptra_drivers::cprintln;

/// Execute Known Answer Tests
///
/// # Arguments
///
/// * `env` - ROM Environment
pub fn execute_kat(env: &mut KatsEnv) -> CaliptraResult<()> {
    cprintln!("[kat] ++");

    

    cprintln!("[kat] --");

    Ok(())
}
