/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for HMAC-384 cryptography operations.

--*/

use crate::caliptra_err_def;
use caliptra_drivers::{Array4x12, CaliptraResult, Hmac384};

caliptra_err_def! {
    Hmac384Kat,
    Hmac384KatErr
    {
        HmacFailure = 0x01,
        HmacTagMismatch = 0x02,
    }
}

const KEY: Array4x12 = Array4x12::new([
    0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b,
    0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b,
]);

const EXPECTED_TAG: Array4x12 = Array4x12::new([
    0xb93a3e87, 0xa1bc85c8, 0x7b54f81d, 0xabb499a5, 0xe1a66254, 0x9198594c, 0x9088733c, 0x8edd0068,
    0x83e4d461, 0x823e6259, 0x8b07a904, 0x28f9add9,
]);

#[derive(Default, Debug)]
pub struct Hmac384Kat {}

impl Hmac384Kat {
    /// This function executes the Known Answer Tests (aka KAT) for HMAC384.
    ///
    /// Test vector source:
    /// Generated using MbedTLS library.
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self, hmac: &mut Hmac384) -> CaliptraResult<()> {
        self.kat_no_data(hmac)?;
        Ok(())
    }

    /// Performs tag generation of a zero size buffer.
    ///
    /// # Arguments
    ///
    /// * `hmac` - HMAC-384 Driver
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn kat_no_data(&self, hmac: &mut Hmac384) -> CaliptraResult<()> {
        let data = &[];
        let mut tag = Array4x12::default();

        hmac.hmac((&KEY).into(), data.into(), (&mut tag).into())
            .map_err(|_| err_u32!(HmacFailure))?;

        if tag != EXPECTED_TAG {
            raise_err!(HmacTagMismatch);
        }

        Ok(())
    }
}
