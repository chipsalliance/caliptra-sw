/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_kdf_kat.rs

Abstract:

    File contains the Known Answer Tests (KAT) for Counter Mode KDF using CMAC.

--*/

// From ACVP test vector:
// "tgId": 263,
// "keyOutLength": 1024,
// "kdfMode": "counter",
// "macMode": "CMAC-AES256",
// "counterLength": 32,
// "counterLocation": "before fixed data",
// "testType": "AFT",
// "tests": [
// {
//     "tcId": 525,
//     "keyIn": "BFB99C6AAB859A9873ACC9880BD875BB83A8B24A9307576A054216908756BE5B"
// },
// "fixedData": "CD9B9791F5EEE211918BA1E2B01B4E29",
// "keyOut": "C303887FB0ACA8E78DEBB8A008E75C88C26E927F0FA8A1DF1614C97E1B6F78B35C8F8A1CB9CD9F18DC30D06C73B75FDEA5A636ACB92F690FC6CB060F0A3DB66E759E30097C297E56C59DB8E17FF2656A8520D7309307B8E161B091FDDAF375B34E2EB8084D2832621C37BB67F09AAB29F3E467F422270B237D9B5AEBAD2D1F05"

use caliptra_drivers::{cmac_kdf, Aes, CaliptraError, CaliptraResult, LEArray4x16};

const KEY_IN: [u8; 32] = [
    0xbf, 0xb9, 0x9c, 0x6a, 0xab, 0x85, 0x9a, 0x98, 0x73, 0xac, 0xc9, 0x88, 0x0b, 0xd8, 0x75, 0xbb,
    0x83, 0xa8, 0xb2, 0x4a, 0x93, 0x07, 0x57, 0x6a, 0x05, 0x42, 0x16, 0x90, 0x87, 0x56, 0xbe, 0x5b,
];

const FIXED_DATA: [u8; 16] = [
    0xcd, 0x9b, 0x97, 0x91, 0xf5, 0xee, 0xe2, 0x11, 0x91, 0x8b, 0xa1, 0xe2, 0xb0, 0x1b, 0x4e, 0x29,
];

const KEY_OUT: LEArray4x16 = LEArray4x16::new([
    0xc303887f, 0xb0aca8e7, 0x8debb8a0, 0x08e75c88, 0xc26e927f, 0x0fa8a1df, 0x1614c97e, 0x1b6f78b3,
    0x5c8f8a1c, 0xb9cd9f18, 0xdc30d06c, 0x73b75fde, 0xa5a636ac, 0xb92f690f, 0xc6cb060f, 0x0a3db66e,
]);

#[derive(Default, Debug)]
pub struct CmacKdfKat {}

impl CmacKdfKat {
    /// This function executes the Known Answer Tests (aka KAT) for CMAC KDF.
    pub fn execute(&self, aes: &mut Aes) -> CaliptraResult<()> {
        let output = cmac_kdf(
            aes,
            caliptra_drivers::AesKey::Array(&KEY_IN),
            &FIXED_DATA,
            None,
            4,
        )?;

        if KEY_OUT != output {
            Err(CaliptraError::KAT_CMAC_KDF_OUTPUT_MISMATCH)?;
        }

        Ok(())
    }
}
