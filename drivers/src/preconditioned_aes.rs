/*++

Licensed under the Apache-2.0 license.

File Name:

    preconditioned_aes.rs

Abstract:

    Preconditioned AES-Encrypt as defined in https://chipsalliance.github.io/Caliptra/ocp-lock/specification/HEAD/#fig:preconditioned-aes-encrypt.

--*/

use crate::{
    hkdf_extract, hmac_kdf, Aes, AesGcmContext, AesGcmIv, AesKey, AesOperation, Hmac, HmacData,
    HmacKey, HmacMode, HmacTag, KeyReadArgs, KeyUsage, KeyWriteArgs, LEArray4x8, Trng,
    AES_BLOCK_SIZE_BYTES,
};

use caliptra_registers::aes::AesReg;
use caliptra_registers::aes_clp::AesClpReg;

use caliptra_error::{CaliptraError, CaliptraResult};

type AesKeyBlock = LEArray4x8;

/// InKey: SP 800-108 KDF Key the subkeys are dervied from
pub fn preconditioned_aes256_enc(
    trng: &mut Trng,
    key: &AesKeyBlock, // SP 800-108 KDF Key the subkeys are dervied from
    iv: AesGcmIv,
    aad: &[u8], // optional metadata for the message, leave empty if not used
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> CaliptraResult<(usize, [u8; AES_BLOCK_SIZE_BYTES])> {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };

    let key_0 = Array4x12::from(key_0);
    let kdf_key_out = KeyWriteArgs::new(
        KeyId::KeyId0,
        KeyUsage::default().set_hmac_key_en().set_hmac_data_en(),
    );
    let kdf_key_in = KeyReadArgs::new(KeyId::KeyId0);

    hmac384
        .hmac(
            (&key_0).into(),
            msg_0.into(),
            &mut trng,
            kdf_key_out.into(),
            HmacMode::Hmac384,
        )
        .unwrap();

    let kdf_out = KeyWriteArgs::new(KeyId::KeyId1, KeyUsage::default().set_ecc_key_gen_seed_en());
    let context = Some(aad);
    let label = &[0u8; 10];

    // SP 800-108 (salt, key, label) -> AESSubKey
    // hkdf_extract(hmac, ikm, salt, trng, prk, mode)
    hmac_kdf(
        &mut hmac384,
        kdf_key_in.into(),
        label,
        context,
        &mut trng,
        kdf_out.into(),
        HmacMode::Hmac384,
    )
    .unwrap();

    let mut aes = unsafe { Aes::new(AesReg::new(), AesClpReg::new()) };
    let aes_gcm_ctx = aes.aes_256_gcm_init(trng, key, iv, aad)?;

    // aes.aes_256_gcm_encrypt_update(context, plaintext, ciphertext)
    return aes.aes_256_gcm_encrypt_final(&aes_gcm_ctx, plaintext, ciphertext);
}
