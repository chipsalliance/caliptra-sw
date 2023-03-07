/*++

Licensed under the Apache-2.0 license.

File Name:

    crypto_kat.rs

Abstract:

    File contains function to execute all the Known Answer Tests (KAT) for cryptography operations.

--*/

use crate::Ecc384Kat;
use crate::Hmac384Kat;
use crate::Sha1Kat;
use crate::Sha256Kat;
use crate::Sha384AccKat;
use crate::Sha384Kat;
use caliptra_lib::CaliptraResult;

#[derive(Default, Debug)]
pub struct CryptoKat {}

impl CryptoKat {
    // This function executes all the  Known Answer Tests (aka KAT).
    //
    // # Arguments
    //
    /// * None
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    #[allow(unused)]
    pub fn execute(&self) -> CaliptraResult<()> {
        Sha1Kat::default().execute()?;
        Sha256Kat::default().execute()?;
        Sha384Kat::default().execute()?;
        Sha384AccKat::default().execute()?;
        Hmac384Kat::default().execute()?;
        Ecc384Kat::default().execute()?;
        Ok(())
    }
}
