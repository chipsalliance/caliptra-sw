/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac384_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for HMAC-384 cryptography operations.

--*/

use caliptra_lib::{caliptra_err_def, Array4x12, Array4xN, CaliptraResult, Hmac384};

caliptra_err_def! {
    Hmac384,
    Hmac384KatErr
    {
        // "No Data Test" failure
        NoDataTestFailure = 0x01,
    }
}

#[derive(Default, Debug)]
pub struct Hmac384Kat {}

impl Hmac384Kat {
    // This function executes the Known Answer Tests (aka KAT) for HMAC384.
    //
    // Test vector source:
    // Generated using MbedTLS library.
    //
    // # Arguments
    //
    /// * None
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    pub fn execute(&self) -> CaliptraResult<()> {
        self.kat_no_data()?;
        Ok(())
    }

    // Performs tag generation of a zero size buffer.
    //
    // # Arguments
    //
    /// * None
    ///
    /// # Returns
    ///
    /// * `CaliptraResult` - Result denoting the KAT outcome.
    fn kat_no_data(&self) -> CaliptraResult<()> {
        let key = Array4xN([
            0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b,
            0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b, 0xb0b0b0b,
        ]);
        let data = &[];
        let expected_tag = Array4xN([
            0xb93a3e87, 0xa1bc85c8, 0x7b54f81d, 0xabb499a5, 0xe1a66254, 0x9198594c, 0x9088733c,
            0x8edd0068, 0x83e4d461, 0x823e6259, 0x8b07a904, 0x28f9add9,
        ]);
        let mut tag = Array4x12::default();
        let result = Hmac384::default().hmac((&key).into(), data.into(), (&mut tag).into());
        if result.is_err() || tag != expected_tag {
            raise_err!(NoDataTestFailure);
        }
        Ok(())
    }
}
