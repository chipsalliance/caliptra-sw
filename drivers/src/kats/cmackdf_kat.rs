/*++

Licensed under the Apache-2.0 license.

File Name:

    cmackdf_kat.rs

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

use crate::{
    aes::Aes, cmac_kdf, cprintln, AesKey, CaliptraError, CaliptraResult, LEArray4x16, LEArray4x8,
};

const KEY_IN: LEArray4x8 = LEArray4x8::new([
    0x6a9cb9bf, 0x989a85ab, 0x88c9ac73, 0xbb75d80b, 0x4ab2a883, 0x6a570793, 0x90164205, 0x5bbe5687,
]);

const FIXED_DATA: [u8; 16] = [
    0xcd, 0x9b, 0x97, 0x91, 0xf5, 0xee, 0xe2, 0x11, 0x91, 0x8b, 0xa1, 0xe2, 0xb0, 0x1b, 0x4e, 0x29,
];

const KEY_OUT: LEArray4x16 = LEArray4x16::new([
    0x7f8803c3, 0xe7a8acb0, 0xa0b8eb8d, 0x885ce708, 0x7f926ec2, 0xdfa1a80f, 0x7ec91416, 0xb3786f1b,
    0x1c8a8f5c, 0x189fcdb9, 0x6cd030dc, 0xde5fb773, 0xac36a6a5, 0x0f692fb9, 0x0f06cbc6, 0x6eb63d0a,
]);

/// Execute the CMAC-KDF Known Answer Test.
pub fn execute_cmackdf_kat(aes: &mut Aes) -> CaliptraResult<()> {
    cprintln!("[kat] KDF-CMAC");
    let output = cmac_kdf(aes, AesKey::Array(&KEY_IN), &FIXED_DATA, None, 4)?;

    if KEY_OUT != output {
        Err(CaliptraError::KAT_CMAC_KDF_OUTPUT_MISMATCH)?;
    }

    Ok(())
}
