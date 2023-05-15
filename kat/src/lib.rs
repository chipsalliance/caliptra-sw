/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains exports for the Caliptra Known Answer Tests.

--*/

#![no_std]

mod ecc384_kat;
mod hmac384_kat;
mod sha1_kat;
mod sha256_kat;
mod sha384_kat;
mod sha384acc_kat;

pub use caliptra_drivers::{caliptra_err_def, CaliptraComponent, CaliptraError, CaliptraResult};
pub use ecc384_kat::Ecc384Kat;
pub use hmac384_kat::Hmac384Kat;
pub use sha1_kat::Sha1Kat;
pub use sha256_kat::Sha256Kat;
pub use sha384_kat::Sha384Kat;
pub use sha384acc_kat::Sha384AccKat;
