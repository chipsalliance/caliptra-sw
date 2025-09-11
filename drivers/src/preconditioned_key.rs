/*++

Licensed under the Apache-2.0 license.

File Name:

    preconditioned_key.rs

Abstract:

    A FIPS-approved method for combining keys together leveraging an HMAC-based key-extraction process.

--*/

use crate::{
    hmac_kdf, Aes, AesKey, AesOperation, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyReadArgs,
    KeyUsage, KeyWriteArgs, LEArray4x8, Trng,
};

use caliptra_error::{CaliptraError, CaliptraResult};

pub fn preconditioned_key_extract(
    input_key: HmacKey,
    output_key: HmacTag,
    kdf_label: &[u8],
    salt: HmacKey,
    trng: &mut Trng,
    hmac: &mut Hmac,
    aes: &mut Aes,
) -> CaliptraResult<()> {
    let HmacTag::Key(output_kv) = output_key else {
        Err(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_KEY_INVALID_INPUT)?
    };

    let aes_key;
    let aes_key = match salt {
        HmacKey::Array4x16(arr) => {
            let mut aes_arr: [u32; 8] = [0; 8];
            // Truncate HMAC Key from 64 bytes to 32 bytes.
            aes_arr.clone_from_slice(&arr.0[..8]);
            // Swap bytes before converting to LEArray4x8.
            for byte in aes_arr.iter_mut() {
                *byte = byte.swap_bytes();
            }
            aes_key = LEArray4x8::from(&aes_arr);
            AesKey::Array(&aes_key)
        }
        HmacKey::Key(kv) => AesKey::KV(kv),
        _ => Err(CaliptraError::RUNTIME_DRIVER_PRECONDITIONED_KEY_INVALID_INPUT)?,
    };

    let mut checksum = [0; 16];
    aes.aes_256_ecb(aes_key, AesOperation::Encrypt, &[0; 16], &mut checksum)?;

    hmac_kdf(
        hmac,
        input_key,
        kdf_label,
        Some(&checksum),
        trng,
        HmacTag::Key(KeyWriteArgs::new(
            output_kv.id,
            KeyUsage::default().set_hmac_data_en(),
        )),
        HmacMode::Hmac512,
    )?;

    hmac.hmac(
        salt,
        HmacData::Key(KeyReadArgs::new(output_kv.id)),
        trng,
        HmacTag::Key(output_kv),
        HmacMode::Hmac512,
    )?;
    Ok(())
}
