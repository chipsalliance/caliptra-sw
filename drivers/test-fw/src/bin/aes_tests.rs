/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_tests.rs

Abstract:

    File contains test cases for AES.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    Aes, AesIv, AesKey, Array4x12, Hmac, HmacData, HmacKey, HmacMode, HmacTag, KeyId, KeyReadArgs,
    KeyUsage, KeyWriteArgs, Trng,
};
use caliptra_kat::Aes256GcmKat;
use caliptra_registers::aes::AesReg;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;

use caliptra_test_harness::test_suite;

fn test_aes_kv() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };

    let zeros = [0u8; 48];
    let zero_key: Array4x12 = zeros.into();

    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    //
    // Step 1: Place a known key in the key-vault.
    //
    let mut out = Array4x12::default();
    hmac384
        .hmac(
            &HmacKey::Array4x12(&zero_key),
            &HmacData::Slice(&zeros[..]),
            &mut trng,
            HmacTag::Array4x12(&mut out),
            HmacMode::Hmac384,
        )
        .unwrap();

    // the output is 7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5

    let out: [u8; 48] = out.into();
    assert_eq!(
        out,
        [
            0x7e, 0xe8, 0x20, 0x6f, 0x55, 0x70, 0x2, 0x3e, 0x6d, 0xc7, 0x51, 0x9e, 0xb1, 0x7, 0x3b,
            0xc4, 0xe7, 0x91, 0xad, 0x37, 0xb5, 0xc3, 0x82, 0xaa, 0x10, 0xba, 0x18, 0xe2, 0x35,
            0x7e, 0x71, 0x69, 0x71, 0xf9, 0x36, 0x2f, 0x2c, 0x2f, 0xe2, 0xa7, 0x6b, 0xfd, 0x78,
            0xdf, 0xec, 0x4e, 0xa9, 0xb5
        ]
    );

    let mut key = [0u8; 32];
    key.copy_from_slice(&out[0..32]);

    let mut aes = unsafe { Aes::new(AesReg::new()) };

    aes.init_masking(&mut trng).unwrap();

    let iv = [0u8; 12];

    let pt = [0u8; 16];
    let mut ct = [0u8; 16];

    aes.aes_256_gcm_encrypt(
        &mut trng,
        AesIv::Array(&iv),
        AesKey::Array(&key),
        &[],
        &pt[..],
        &mut ct[..],
        16,
    )
    .unwrap();

    assert_eq!(
        ct,
        [
            0x4d, 0xa9, 0x81, 0x57, 0xc7, 0xb, 0xd2, 0x0, 0x10, 0x25, 0x45, 0xc6, 0xa9, 0xc5, 0xb5,
            0xe4
        ]
    );

    // load into key vault
    hmac384
        .hmac(
            &HmacKey::Array4x12(&zero_key),
            &HmacData::Slice(&zeros[..]),
            &mut trng,
            HmacTag::Key(KeyWriteArgs::new(
                KeyId::KeyId10,
                KeyUsage::default().set_aes_key_en(),
            )),
            HmacMode::Hmac384,
        )
        .unwrap();

    let mut ct2 = [0u8; 16];

    aes.aes_256_gcm_encrypt(
        &mut trng,
        AesIv::Array(&iv),
        AesKey::Key(KeyReadArgs::new(KeyId::KeyId10).into()),
        &[],
        &pt[..],
        &mut ct2[..],
        16,
    )
    .unwrap();

    assert_eq!(
        ct2,
        [
            0x4d, 0xa9, 0x81, 0x57, 0xc7, 0xb, 0xd2, 0x0, 0x10, 0x25, 0x45, 0xc6, 0xa9, 0xc5, 0xb5,
            0xe4
        ]
    );
}

fn test_kat() {
    let mut aes = unsafe { Aes::new(AesReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    assert!(Aes256GcmKat::default().execute(&mut aes, &mut trng).is_ok());
}

// test_kat MUST be ran first.
test_suite! {
    test_kat,
    test_aes_kv,
}
