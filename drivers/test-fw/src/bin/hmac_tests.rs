/*++

Licensed under the Apache-2.0 license.

File Name:

    hmac_tests.rs

Abstract:

    File contains test cases for HMAC-384 and HMAC-512 API

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    hmac384_kdf, Array4x12, Array4x16, Ecc384, Ecc384PrivKeyOut, Ecc384Scalar, Ecc384Seed, Hmac, HmacMode,
    KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, Trng,
};
use caliptra_kat::Hmac384KdfKat;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::ecc::EccReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::hmac::HmacReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;

use caliptra_test_harness::test_suite;

fn test_hmac0() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 48] = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b,
    ];

    let data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];

    let result: [u8; 48] = [
        0xb6, 0xa8, 0xd5, 0x63, 0x6f, 0x5c, 0x6a, 0x72, 0x24, 0xf9, 0x97, 0x7d, 0xcf, 0x7e, 0xe6,
        0xc7, 0xfb, 0x6d, 0x0c, 0x48, 0xcb, 0xde, 0xe9, 0x73, 0x7a, 0x95, 0x97, 0x96, 0x48, 0x9b,
        0xdd, 0xbc, 0x4c, 0x5d, 0xf6, 0x1d, 0x5b, 0x32, 0x97, 0xb4, 0xfb, 0x68, 0xda, 0xb9, 0xf1,
        0xb5, 0x82, 0xc2,
    ];

    let mut out_tag = Array4x12::default();
    let actual = hmac.hmac(
        &(&Array4x12::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac384,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));
}

fn test_hmac1() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    let key: [u8; 48] = [
        0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66,
        0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
        0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a,
        0x65, 0x66, 0x65,
    ];

    let data: [u8; 28] = [
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
    ];

    let result: [u8; 48] = [
        0x2c, 0x73, 0x53, 0x97, 0x4f, 0x18, 0x42, 0xfd, 0x66, 0xd5, 0x3c, 0x45, 0x2c, 0xa4, 0x21,
        0x22, 0xb2, 0x8c, 0x0b, 0x59, 0x4c, 0xfb, 0x18, 0x4d, 0xa8, 0x6a, 0x36, 0x8e, 0x9b, 0x8e,
        0x16, 0xf5, 0x34, 0x95, 0x24, 0xca, 0x4e, 0x82, 0x40, 0x0c, 0xbd, 0xe0, 0x68, 0x6d, 0x40,
        0x33, 0x71, 0xc9,
    ];

    let mut out_tag = Array4x12::default();
    let actual = hmac384.hmac(
        &(&Array4x12::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac384,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));
}

fn test_kv_hmac(seed: &[u8; 48], data: &[u8], out_pub_x: &[u8; 48], out_pub_y: &[u8; 48]) {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };
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
    // Step 1: Place a key in the key-vault.
    //
    ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        KeyWriteArgs::new(
            KeyId::KeyId0,
            KeyUsage::default()
                .set_hmac_key_en()
                .set_ecc_private_key_en(),
        )
        .into(),
    )
    .unwrap();

    //
    // Step 2: Hash the data with the key from key-vault.
    //
    hmac384
        .hmac(
            &KeyReadArgs::new(KeyId::KeyId0).into(),
            &data.into(),
            &mut trng,
            KeyWriteArgs::new(KeyId::KeyId1, KeyUsage::default().set_ecc_key_gen_seed_en()).into(),
            HmacMode::Hmac384,
        )
        .unwrap();

    let pub_key = ecc
        .key_pair(
            &KeyReadArgs::new(KeyId::KeyId1).into(),
            &Array4x12::default(),
            &mut trng,
            KeyWriteArgs::new(KeyId::KeyId2, KeyUsage::default().set_ecc_private_key_en()).into(),
        )
        .unwrap();

    assert_eq!(pub_key.x, Array4x12::from(out_pub_x));
    assert_eq!(pub_key.y, Array4x12::from(out_pub_y));
}

fn test_hmac2() {
    let seed = [
        0x58, 0x8d, 0xe9, 0x0e, 0x26, 0xd0, 0x46, 0x6d, 0x8d, 0xdb, 0xb5, 0xd7, 0x47, 0x20, 0x3c,
        0x9b, 0x6f, 0xab, 0xaa, 0xcb, 0x1f, 0x3c, 0xeb, 0xbf, 0x8b, 0x1c, 0x0b, 0x98, 0x00, 0xbb,
        0xf9, 0xbc, 0x01, 0x52, 0x06, 0x89, 0x37, 0xc9, 0x6f, 0x0b, 0x8b, 0x12, 0x46, 0x4b, 0x3c,
        0x2c, 0xde, 0xea,
    ];
    let data = [0x64, 0xab, 0x1f, 0x00, 0x23, 0x75, 0xdc, 0x00];
    let out_pub_x = [
        0xde, 0x54, 0x96, 0xfe, 0x72, 0xb2, 0xa4, 0x75, 0x52, 0x06, 0x3f, 0x87, 0x4b, 0xd1, 0x0a,
        0x57, 0x26, 0x98, 0x0d, 0xb9, 0x34, 0xaf, 0x36, 0x41, 0xc4, 0xb9, 0xe7, 0xa1, 0x8e, 0x45,
        0x90, 0xd6, 0xce, 0xf6, 0x82, 0xdd, 0x93, 0xce, 0x6b, 0xf4, 0x09, 0xae, 0x39, 0x13, 0x90,
        0x3e, 0xab, 0xeb,
    ];
    let out_pub_y = [
        0x85, 0x95, 0xa2, 0xc0, 0x7c, 0x2e, 0x89, 0x33, 0x91, 0x4f, 0x52, 0xf8, 0x6d, 0xa3, 0x4c,
        0xf1, 0x01, 0x33, 0x24, 0x0c, 0x50, 0x4e, 0xd2, 0x53, 0x53, 0x79, 0x29, 0x80, 0x06, 0x0a,
        0x47, 0x90, 0x89, 0x11, 0x0c, 0xd2, 0xe8, 0x00, 0x30, 0x6e, 0x22, 0x98, 0x30, 0xbc, 0xa6,
        0x76, 0xe8, 0xd5,
    ];

    test_kv_hmac(&seed, &data, &out_pub_x, &out_pub_y);
}

fn test_hmac3() {
    let seed = [
        0x0e, 0xd2, 0xca, 0x91, 0x29, 0x1b, 0x3b, 0x8d, 0xa5, 0xab, 0xb4, 0x77, 0x15, 0x75, 0x1a,
        0xca, 0xe0, 0x85, 0x7e, 0x56, 0x88, 0xd4, 0x8c, 0xcb, 0xc9, 0xad, 0x50, 0xf8, 0xa1, 0x3e,
        0xdf, 0x3c, 0x1a, 0x47, 0x01, 0xf7, 0x90, 0x05, 0xa5, 0x65, 0x52, 0x37, 0xf5, 0x92, 0x79,
        0x95, 0x68, 0x22,
    ];
    let data = [
        0x01, 0x7a, 0x3a, 0x10, 0xf8, 0x1f, 0xd4, 0x2a, 0xc7, 0xb6, 0x4c, 0x7c, 0xab, 0x37, 0x4e,
        0xed, 0xde, 0xcc, 0x3f, 0xff, 0x9a, 0x62, 0x58, 0xbd, 0x98, 0x17, 0x37, 0x14,
    ];
    let out_pub_x = [
        0xe3, 0x86, 0xfb, 0x91, 0xd8, 0xc9, 0x3e, 0x23, 0x44, 0xe2, 0xfd, 0x21, 0x11, 0x6e, 0x74,
        0x89, 0xf6, 0x32, 0xde, 0x8d, 0xa9, 0x47, 0xb3, 0x04, 0x6e, 0xb5, 0x59, 0xf4, 0x2a, 0x96,
        0xd9, 0x3a, 0x77, 0x41, 0x4c, 0xed, 0x0b, 0x9c, 0x97, 0xf8, 0xa6, 0xc0, 0x3e, 0x3e, 0x3b,
        0xac, 0x47, 0x9b,
    ];
    let out_pub_y = [
        0xa3, 0xd2, 0x8b, 0x8d, 0xae, 0x31, 0x3a, 0xe3, 0x76, 0x03, 0xab, 0xa1, 0x88, 0xd7, 0x70,
        0xfb, 0xce, 0x75, 0x6a, 0xeb, 0x40, 0x1e, 0xbb, 0x01, 0x1b, 0x88, 0xa3, 0xf2, 0x91, 0x1d,
        0x11, 0xda, 0x57, 0xba, 0x09, 0xe2, 0xf6, 0x1f, 0xc5, 0xec, 0xed, 0x14, 0xf8, 0xf5, 0x12,
        0x53, 0x8b, 0x25,
    ];

    test_kv_hmac(&seed, &data, &out_pub_x, &out_pub_y);
}

fn test_hmac4() {
    let seed = [
        0x32, 0x36, 0xcf, 0xba, 0x5d, 0xf3, 0x86, 0x39, 0x3e, 0x41, 0x13, 0x2b, 0x2d, 0x70, 0x6c,
        0x00, 0x66, 0xe9, 0x2a, 0xa7, 0xb6, 0xe7, 0x09, 0x35, 0x16, 0xb6, 0xeb, 0x5f, 0x0b, 0x1e,
        0x09, 0x3d, 0x7c, 0x9f, 0xa8, 0x1a, 0x0e, 0x61, 0x23, 0xac, 0x09, 0x0a, 0x40, 0xa4, 0x42,
        0xf9, 0x3f, 0xaa,
    ];
    let data = [
        0x35, 0xc8, 0x57, 0xb5, 0x0f, 0x0f, 0xb2, 0x1a, 0x39, 0xab, 0xc8, 0xa3, 0xe7, 0xed, 0xf7,
        0xe0, 0x4f, 0x16, 0xa4, 0xd5, 0xe6, 0x86, 0xe3, 0xf2, 0x1f, 0x38, 0xf5, 0x6e, 0xbd, 0x88,
        0x74, 0x3f, 0x0f, 0xfb, 0x27, 0x29, 0x60, 0x3f, 0x84, 0x07, 0x5e, 0x5e, 0xc4, 0x57, 0x79,
        0xce, 0xfa, 0x30,
    ];
    let out_pub_x = [
        0x21, 0x00, 0xca, 0xc8, 0x6d, 0xa4, 0x88, 0xa0, 0x39, 0xbd, 0x91, 0x52, 0x6e, 0xc0, 0x46,
        0x47, 0x9b, 0x46, 0x6b, 0x99, 0x2a, 0x31, 0x7d, 0xba, 0xea, 0xd6, 0x6d, 0xc9, 0x1e, 0x20,
        0xa1, 0x8e, 0xa6, 0x6d, 0x60, 0xc4, 0xf8, 0xd0, 0xd7, 0x8f, 0x85, 0x10, 0x35, 0x12, 0x38,
        0x90, 0xb4, 0x7d,
    ];
    let out_pub_y = [
        0x54, 0xc3, 0xa0, 0x20, 0xc6, 0x9b, 0xe9, 0x21, 0xc1, 0x8d, 0xb1, 0x19, 0xac, 0xa9, 0xdd,
        0x10, 0x28, 0xa9, 0x4f, 0x93, 0x1b, 0x77, 0xea, 0xaa, 0x0c, 0x5e, 0x38, 0x08, 0x71, 0xfa,
        0x4b, 0xd7, 0x0b, 0x10, 0x5f, 0xf1, 0x23, 0x86, 0xef, 0x5f, 0x6d, 0xa2, 0xc5, 0x72, 0x44,
        0xd5, 0x7e, 0xbf,
    ];

    test_kv_hmac(&seed, &data, &out_pub_x, &out_pub_y);
}

fn test_hmac_kv_multiblock() {
    let seed = [
        0x32, 0x36, 0xcf, 0xba, 0x5d, 0xf3, 0x86, 0x39, 0x3e, 0x41, 0x13, 0x2b, 0x2d, 0x70, 0x6c,
        0x00, 0x66, 0xe9, 0x2a, 0xa7, 0xb6, 0xe7, 0x09, 0x35, 0x16, 0xb6, 0xeb, 0x5f, 0x0b, 0x1e,
        0x09, 0x3d, 0x7c, 0x9f, 0xa8, 0x1a, 0x0e, 0x61, 0x23, 0xac, 0x09, 0x0a, 0x40, 0xa4, 0x42,
        0xf9, 0x3f, 0xaa,
    ];

    let data: [u8; 256] = [
        0x35, 0xc8, 0x57, 0xb5, 0x0f, 0x0f, 0xb2, 0x1a, 0x39, 0xab, 0xc8, 0xa3, 0xe7, 0xed, 0xf7,
        0xe0, 0x4f, 0x16, 0xa4, 0xd5, 0xe6, 0x86, 0xe3, 0xf2, 0x1f, 0x38, 0xf5, 0x6e, 0xbd, 0x88,
        0x74, 0x3f, 0x0f, 0xfb, 0x27, 0x29, 0x60, 0x3f, 0x84, 0x07, 0x5e, 0x5e, 0xc4, 0x57, 0x79,
        0xce, 0xfa, 0x30, 0x5b, 0xb2, 0xed, 0xdd, 0xd7, 0xe2, 0xd2, 0xb3, 0xa6, 0x7a, 0xd9, 0x1e,
        0x5d, 0x86, 0xa1, 0x96, 0x67, 0x2a, 0x47, 0x48, 0x4e, 0x72, 0xd6, 0xec, 0xde, 0x96, 0xbe,
        0x5f, 0x9f, 0x09, 0x71, 0xbf, 0xe3, 0xc9, 0x06, 0x59, 0x1a, 0x3b, 0x2e, 0x3b, 0xe8, 0x97,
        0x56, 0x27, 0x13, 0x5e, 0xf7, 0xf3, 0x7c, 0xde, 0xe0, 0x94, 0xdd, 0xf3, 0x3d, 0xa0, 0x7f,
        0xf5, 0x77, 0x47, 0xca, 0x32, 0xbc, 0xb3, 0x0d, 0x6a, 0x40, 0xeb, 0xeb, 0x07, 0x86, 0x01,
        0x27, 0x82, 0x55, 0x6b, 0x8e, 0x0a, 0x48, 0x34, 0x9b, 0x72, 0x91, 0x10, 0x55, 0xeb, 0x2b,
        0x0d, 0x53, 0x2d, 0xe2, 0x6b, 0x62, 0xa4, 0x06, 0xfd, 0x03, 0x9b, 0xfd, 0x74, 0x9d, 0xd3,
        0x59, 0x3d, 0x66, 0xd6, 0xfb, 0x09, 0x83, 0x63, 0x7d, 0xbf, 0x34, 0x40, 0x40, 0x5b, 0xf7,
        0xf8, 0xb0, 0xd3, 0xe8, 0x72, 0x7c, 0x4c, 0xc8, 0xd2, 0x01, 0x8a, 0xf4, 0xc3, 0xf0, 0xff,
        0x12, 0x21, 0x17, 0xfb, 0x6a, 0x44, 0x00, 0x52, 0xc2, 0x0c, 0x6a, 0x9b, 0x93, 0x21, 0xd1,
        0x65, 0x22, 0x8d, 0xae, 0x70, 0xbf, 0x90, 0xdb, 0xe4, 0x8a, 0x1a, 0xb9, 0x79, 0x48, 0x7a,
        0x35, 0x6d, 0x96, 0x29, 0x22, 0x82, 0xd1, 0xfb, 0x06, 0x42, 0x09, 0xbc, 0xe5, 0xd0, 0x1c,
        0xec, 0xf5, 0xc1, 0x74, 0x13, 0x4d, 0x89, 0x4a, 0xae, 0xdb, 0xfb, 0xe6, 0xe0, 0x21, 0x89,
        0x32, 0xad, 0xa2, 0x0e, 0xcb, 0xc0, 0x96, 0xc7, 0x01, 0xc5, 0xf8, 0x3b, 0xee, 0xf8, 0x4c,
        0x6a,
    ];

    let out_pub_x = [
        0x75, 0x08, 0xb8, 0xfe, 0x7f, 0x1e, 0x44, 0x19, 0x1b, 0x12, 0x4e, 0xd6, 0x11, 0x7b, 0x1d,
        0x0b, 0xce, 0x6d, 0xdc, 0x87, 0xf7, 0x1c, 0x0b, 0xb5, 0x5d, 0x88, 0xb7, 0x1a, 0x48, 0x8d,
        0x1b, 0x19, 0x08, 0x3b, 0x30, 0xbf, 0x42, 0x29, 0x2b, 0x8d, 0xf5, 0xdc, 0xd8, 0x0b, 0x89,
        0xc8, 0x23, 0x6d,
    ];
    let out_pub_y = [
        0xab, 0x30, 0x6a, 0x98, 0xa3, 0x75, 0x2d, 0xaa, 0xd2, 0xfd, 0x72, 0xa9, 0x96, 0x85, 0xf4,
        0xcf, 0xe9, 0x8c, 0xbf, 0x0d, 0x94, 0xab, 0x8d, 0x66, 0x86, 0x5e, 0xba, 0x54, 0x56, 0xba,
        0x19, 0x07, 0x4f, 0xd7, 0xfe, 0x3d, 0xc0, 0xa5, 0x56, 0x77, 0xdf, 0x78, 0xab, 0x89, 0x6a,
        0x02, 0x43, 0xb9,
    ];

    test_kv_hmac(&seed, &data, &out_pub_x, &out_pub_y);
}

///
/// Step 1:
/// Key From Key Vault
/// Generate the output tag in the buffer.
/// Generate the HMAC of the output tag in the buffer - step_1 Tag
///
///
/// Step 2:
/// Key From Key Vault
/// Generate the output tag that goes in the KV
/// Generate the HMAC of the tag in KV and the tag goes in specified buffer
///
///
fn test_hmac5() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };
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
    // Step 1: Place a key in the key-vault.
    //
    // Key is [ 0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8, 0x73, 0xf2,
    //          0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e, 0x39, 0x4c, 0xa7, 0x84,
    //          0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9, 0x3e, 0xe, 0xab, 0x89, 0x46, 0xd6,];
    //
    let seed = [0u8; 48];
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId0,
        usage: KeyUsage::default()
            .set_hmac_key_en()
            .set_ecc_private_key_en(),
    };
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());

    // Key vault key to be used for all the operations. This is a constant
    let key = KeyReadArgs::new(KeyId::KeyId0);

    let data: [u8; 28] = [
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
    ];

    // The hardware no longer reveals HMAC results to the CPU that use data from
    // the key-vault, returning all zeroes instead
    let result = [0u8; 48];

    // Take the Data Generate the Tag in buffer
    let mut out_tag = Array4x12::default();
    let actual = hmac384.hmac(
        &key.into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac384,
    );
    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));

    let step_1_result_expected: [u8; 48] = [0u8; 48];

    // Generate the HMAC of the Tag in to a hmac_step_1
    let mut hmac_step_1 = Array4x12::default();
    let actual = hmac384.hmac(
        &key.into(),
        &(&result).into(),
        &mut trng,
        (&mut hmac_step_1).into(),
        HmacMode::Hmac384,
    );
    assert!(actual.is_ok());
    assert_eq!(hmac_step_1, Array4x12::from(step_1_result_expected));

    // Generate the Tag Of Original Data and put the tag In KV @5.  KV @5 will be used as data in the next step
    let out_tag = KeyWriteArgs::new(KeyId::KeyId5, KeyUsage::default().set_hmac_data_en());
    let actual = hmac384.hmac(
        &key.into(),
        &(&data).into(),
        &mut trng,
        out_tag.into(),
        HmacMode::Hmac384,
    );
    assert!(actual.is_ok());

    // Data From Key Vault generate HMAC in to output buffer
    let mut hmac_step_2 = Array4x12::default();
    let data_input: KeyReadArgs = KeyReadArgs::new(KeyId::KeyId5);

    let actual = hmac384.hmac(
        &key.into(),
        &data_input.into(),
        &mut trng,
        (&mut hmac_step_2).into(),
        HmacMode::Hmac384,
    );

    assert!(actual.is_ok());
    assert_eq!(hmac_step_1, hmac_step_2);
}

fn test_kdf(
    key_0: &[u8; 48],
    msg_0: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    out_pub_x: &[u8; 48],
    out_pub_y: &[u8; 48],
) {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut ecc = unsafe { Ecc384::new(EccReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key_0 = Array4x12::from(key_0);
    let kdf_key_out = KeyWriteArgs::new(
        KeyId::KeyId0,
        KeyUsage::default().set_hmac_key_en().set_hmac_data_en(),
    );
    let kdf_key_in = KeyReadArgs::new(KeyId::KeyId0);

    hmac384
        .hmac(
            &(&key_0).into(),
            &(&msg_0.into()),
            &mut trng,
            kdf_key_out.into(),
            HmacMode::Hmac384,
        )
        .unwrap();

    let kdf_out = KeyWriteArgs::new(KeyId::KeyId1, KeyUsage::default().set_ecc_key_gen_seed_en());

    hmac384_kdf(
        &mut hmac384,
        kdf_key_in.into(),
        label,
        context,
        &mut trng,
        kdf_out.into(),
    )
    .unwrap();

    let ecc_out = KeyWriteArgs::new(KeyId::KeyId2, KeyUsage::default().set_ecc_private_key_en());

    let pub_key = ecc
        .key_pair(
            &KeyReadArgs::new(KeyId::KeyId1).into(),
            &Array4x12::default(),
            &mut trng,
            Ecc384PrivKeyOut::from(ecc_out),
        )
        .unwrap();

    assert_eq!(pub_key.x, Array4x12::from(out_pub_x));
    assert_eq!(pub_key.y, Array4x12::from(out_pub_y));
}

// context_len = 48
fn test_kdf0() {
    let key_0 = [
        0x9e, 0x2c, 0xce, 0xc7, 0x00, 0x16, 0x1e, 0x42, 0xff, 0x0e, 0x13, 0x8c, 0x48, 0x89, 0xe4,
        0xd6, 0xa0, 0x88, 0x8d, 0x13, 0x1d, 0x58, 0xcb, 0x44, 0xf5, 0xe2, 0x92, 0x47, 0x59, 0x64,
        0xac, 0x6a, 0x8c, 0x63, 0xff, 0x7c, 0x0c, 0x95, 0xe7, 0xda, 0x0b, 0x4e, 0x17, 0xdf, 0x67,
        0xa5, 0x5c, 0xb6,
    ];
    let msg_0 = [
        0x2c, 0x60, 0xda, 0x7c, 0xd6, 0xfc, 0x88, 0x99, 0x58, 0x3e, 0xf7, 0xa8, 0x10, 0xe7, 0x4b,
        0xb1, 0x37, 0x7b, 0xaa, 0x72, 0x66, 0x38, 0xb4, 0x15, 0x7c, 0x72, 0x41, 0x61, 0x06, 0x93,
        0xcb, 0xc9, 0xb1, 0x78, 0xa7, 0x85, 0x61, 0xeb, 0xa7, 0x5d, 0x0e, 0x65, 0x99, 0x10, 0x49,
        0xd9, 0x57, 0x93,
    ];
    let label = [0x2d, 0xd2, 0x38, 0x86];
    let context = [
        0x9a, 0x81, 0x9e, 0xf0, 0xc9, 0x67, 0xb2, 0x13, 0x88, 0x41, 0x72, 0x1e, 0xd9, 0xde, 0x2f,
        0xd4, 0x1c, 0xb9, 0xa7, 0x7e, 0x78, 0x4e, 0x38, 0x5b, 0x90, 0x36, 0x26, 0x2a, 0xe2, 0x81,
        0xf6, 0x21, 0x93, 0x55, 0x85, 0xf6, 0xf7, 0x59, 0xeb, 0x16, 0xcc, 0xed, 0x7f, 0x65, 0x13,
        0x04, 0xd7, 0x9d,
    ];
    let out_pub_x = [
        0x67, 0x3e, 0x4d, 0x0d, 0x4a, 0x7b, 0x15, 0x17, 0x8a, 0x87, 0x5a, 0x28, 0x3a, 0xa4, 0x98,
        0x80, 0x84, 0x99, 0xf6, 0x91, 0x76, 0xde, 0xaa, 0x52, 0x9f, 0x44, 0xb2, 0xdb, 0x6c, 0x2c,
        0xac, 0xd3, 0x68, 0xe6, 0x8f, 0xdc, 0xdc, 0x7a, 0xfd, 0xef, 0x3f, 0x7f, 0x96, 0xef, 0x95,
        0x0e, 0x08, 0x0a,
    ];
    let out_pub_y = [
        0x34, 0x28, 0x5e, 0x58, 0xb9, 0x4a, 0x3a, 0xcc, 0x1c, 0x4b, 0xb3, 0x8f, 0xca, 0xf4, 0xf9,
        0xc5, 0x91, 0x7c, 0xd7, 0x41, 0xd7, 0x0f, 0x72, 0xae, 0x29, 0x3d, 0xf7, 0x81, 0x76, 0xb4,
        0x6f, 0xfd, 0xc3, 0xf8, 0xf1, 0x99, 0xd6, 0x97, 0x6a, 0x58, 0x63, 0x80, 0xcc, 0x80, 0x76,
        0xcb, 0x13, 0x18,
    ];

    test_kdf(
        &key_0,
        &msg_0,
        &label,
        Some(&context),
        &out_pub_x,
        &out_pub_y,
    );
}

// context_len = 0
fn test_kdf1() {
    let key_0 = [
        0xd3, 0x45, 0xe5, 0x14, 0x19, 0xda, 0xc6, 0x9c, 0x70, 0xc8, 0x22, 0x71, 0xe9, 0x12, 0x28,
        0x58, 0x65, 0x64, 0x16, 0xc9, 0x92, 0xf3, 0xda, 0x58, 0x5a, 0xca, 0x96, 0xe5, 0x99, 0x29,
        0x30, 0x53, 0xc0, 0xba, 0x0b, 0x5d, 0xe8, 0x52, 0xa8, 0x32, 0xd9, 0xb5, 0xe9, 0x4a, 0xf3,
        0xbd, 0x38, 0x1b,
    ];
    let msg_0 = [
        0x46, 0x4c, 0x40, 0xe2, 0xab, 0x31, 0x06, 0x5c, 0x7b, 0x88, 0x0b, 0x6b, 0x32, 0x5d, 0x86,
        0xe4, 0xea, 0x5c, 0x98, 0x08, 0x16, 0xf4, 0x6a, 0x47, 0x60, 0x49, 0x19, 0x5a, 0xa8, 0x65,
        0xa2, 0x5c, 0xc7, 0x89, 0x5f, 0x1a, 0xbd, 0x03, 0x06, 0x9c, 0x16, 0x89, 0xaf, 0x1c, 0xfa,
        0x23, 0x27, 0xa0,
    ];
    let label = [0xef, 0xe5, 0x19, 0x77];
    let out_pub_x = [
        0x95, 0x58, 0xd3, 0xa7, 0xec, 0x5d, 0xe3, 0xf9, 0xb9, 0x22, 0xe5, 0xe5, 0x2e, 0x19, 0x87,
        0x80, 0x74, 0x9f, 0x29, 0x87, 0x7c, 0xb0, 0x0a, 0x2b, 0xcf, 0x27, 0x89, 0x9c, 0x7d, 0x05,
        0xfd, 0xe3, 0xa8, 0xf2, 0x3a, 0xde, 0x40, 0x35, 0x10, 0x4e, 0xfb, 0x5c, 0xf8, 0xe3, 0xf3,
        0xac, 0x54, 0xca,
    ];
    let out_pub_y = [
        0x45, 0x26, 0x18, 0xc9, 0xe7, 0xe1, 0x6d, 0x42, 0xa4, 0x94, 0x3a, 0x5e, 0xc4, 0xfe, 0x79,
        0xb0, 0x29, 0x48, 0x92, 0x95, 0xf4, 0x2e, 0x60, 0xec, 0x3f, 0x64, 0xc6, 0xf3, 0x8b, 0xa7,
        0x68, 0xf5, 0x2e, 0xf0, 0x64, 0x93, 0xb6, 0x73, 0x42, 0x82, 0x0e, 0x37, 0xf8, 0x46, 0x9a,
        0x9a, 0xa4, 0x19,
    ];

    test_kdf(&key_0, &msg_0, &label, None, &out_pub_x, &out_pub_y);
}

// Test using a NIST vector.
fn test_kdf2() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key = [
        0xb5, 0x7d, 0xc5, 0x23, 0x54, 0xaf, 0xee, 0x11, 0xed, 0xb4, 0xc9, 0x05, 0x2a, 0x52, 0x83,
        0x44, 0x34, 0x8b, 0x2c, 0x6b, 0x6c, 0x39, 0xf3, 0x21, 0x33, 0xed, 0x3b, 0xb7, 0x20, 0x35,
        0xa4, 0xab, 0x55, 0xd6, 0x64, 0x8c, 0x15, 0x29, 0xef, 0x7a, 0x91, 0x70, 0xfe, 0xc9, 0xef,
        0x26, 0xa8, 0x1e,
    ];
    let label = [
        0x17, 0xe6, 0x41, 0x90, 0x9d, 0xed, 0xfe, 0xe4, 0x96, 0x8b, 0xb9, 0x5d, 0x7f, 0x77, 0x0e,
        0x45, 0x57, 0xca, 0x34, 0x7a, 0x46, 0x61, 0x4c, 0xb3, 0x71, 0x42, 0x3f, 0x0d, 0x91, 0xdf,
        0x3b, 0x58, 0xb5, 0x36, 0xed, 0x54, 0x53, 0x1f, 0xd2, 0xa2, 0xeb, 0x0b, 0x8b, 0x2a, 0x16,
        0x34, 0xc2, 0x3c, 0x88, 0xfa, 0xd9, 0x70, 0x6c, 0x45, 0xdb, 0x44, 0x11, 0xa2, 0x3b, 0x89,
    ];
    let out = [
        0x59, 0x49, 0xac, 0xf9, 0x63, 0x5a, 0x77, 0x29, 0x79, 0x28, 0xc1, 0xe1, 0x55, 0xd4, 0x3a,
        0x4e, 0x4b, 0xca, 0x61, 0xb1, 0x36, 0x9a, 0x5e, 0xf5, 0x05, 0x30, 0x88, 0x85, 0x50, 0xba,
        0x27, 0x0e, 0x26, 0xbe, 0x4a, 0x42, 0x1c, 0xdf, 0x80, 0xb7,
    ];

    let mut out_buf = Array4x12::default();

    hmac384_kdf(
        &mut hmac384,
        (&Array4x12::from(&key)).into(),
        &label,
        None,
        &mut trng,
        (&mut out_buf).into(),
    )
    .unwrap();

    assert_eq!(<[u8; 48]>::from(out_buf)[..out.len()], out);
}

fn test_hmac_multi_block() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    let key: [u8; 48] = [
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61,
    ];

    let data: [u8; 130] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
        0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    ];

    let result: [u8; 48] = [
        0x70, 0xF1, 0xF6, 0x3C, 0x8C, 0x0A, 0x0D, 0xFE, 0x09, 0x65, 0xE7, 0x3D, 0x79, 0x62, 0x93,
        0xFD, 0x6E, 0xCD, 0x56, 0x43, 0xB4, 0x20, 0x15, 0x46, 0x58, 0x7E, 0xBD, 0x46, 0xCD, 0x07,
        0xE3, 0xEA, 0xE2, 0x51, 0x4A, 0x61, 0xC1, 0x61, 0x44, 0x24, 0xE7, 0x71, 0xCC, 0x4B, 0x7C,
        0xCA, 0xC8, 0xC3,
    ];

    let mut out_tag = Array4x12::default();
    let actual = hmac384.hmac(
        &(&Array4x12::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac384,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));
}

fn test_hmac_exact_single_block() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    let key: [u8; 48] = [
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61,
    ];

    let data: [u8; 130] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
        0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    ];

    let result: [u8; 48] = [
        0x70, 0xF1, 0xF6, 0x3C, 0x8C, 0x0A, 0x0D, 0xFE, 0x09, 0x65, 0xE7, 0x3D, 0x79, 0x62, 0x93,
        0xFD, 0x6E, 0xCD, 0x56, 0x43, 0xB4, 0x20, 0x15, 0x46, 0x58, 0x7E, 0xBD, 0x46, 0xCD, 0x07,
        0xE3, 0xEA, 0xE2, 0x51, 0x4A, 0x61, 0xC1, 0x61, 0x44, 0x24, 0xE7, 0x71, 0xCC, 0x4B, 0x7C,
        0xCA, 0xC8, 0xC3,
    ];

    let mut out_tag = Array4x12::default();
    let actual = hmac384.hmac(
        &(&Array4x12::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac384,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));
}

fn test_hmac_multi_block_two_step() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };
    let key: [u8; 48] = [
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61,
    ];

    let data: [u8; 130] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
        0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
    ];

    let result: [u8; 48] = [
        0x70, 0xF1, 0xF6, 0x3C, 0x8C, 0x0A, 0x0D, 0xFE, 0x09, 0x65, 0xE7, 0x3D, 0x79, 0x62, 0x93,
        0xFD, 0x6E, 0xCD, 0x56, 0x43, 0xB4, 0x20, 0x15, 0x46, 0x58, 0x7E, 0xBD, 0x46, 0xCD, 0x07,
        0xE3, 0xEA, 0xE2, 0x51, 0x4A, 0x61, 0xC1, 0x61, 0x44, 0x24, 0xE7, 0x71, 0xCC, 0x4B, 0x7C,
        0xCA, 0xC8, 0xC3,
    ];

    let mut out_tag = Array4x12::default();
    let mut hmac_op = hmac384
        .hmac_init(
            &(&Array4x12::from(key)).into(),
            &mut trng,
            (&mut out_tag).into(),
            HmacMode::Hmac384,
        )
        .unwrap();
    assert!(hmac_op.update(&data).is_ok());
    let actual = hmac_op.finalize();
    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x12::from(result));
}

// This test initializes CFI and MUST be ran first.
fn test_kat() {
    let mut hmac384 = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    // Init CFI
    let mut entropy_gen = || trng.generate().map(|a| a.0);
    CfiCounter::reset(&mut entropy_gen);

    assert!(
        Hmac384KdfKat::default()
        .execute(&mut hmac384, &mut trng)
        .is_ok()
    );
}

fn test_hmac0_512() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 64] = [
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
    ];

    let data: [u8; 8] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];

    let result: [u8; 64] = [
        0x63, 0x7e, 0xdc, 0x6e, 0x01, 0xdc, 0xe7, 0xe6, 0x74, 0x2a, 0x99, 0x45, 0x1a, 0xae, 0x82,
        0xdf, 0x23, 0xda, 0x3e, 0x92, 0x43, 0x9e, 0x59, 0x0e, 0x43, 0xe7, 0x61, 0xb3, 0x3e, 0x91,
        0x0f, 0xb8, 0xac, 0x28, 0x78, 0xeb, 0xd5, 0x80, 0x3f, 0x6f, 0x0b, 0x61, 0xdb, 0xce, 0x5e,
        0x25, 0x1f, 0xf8, 0x78, 0x9a, 0x47, 0x22, 0xc1, 0xbe, 0x65, 0xae, 0xa4, 0x5f, 0xd4, 0x64,
        0xe8, 0x9f, 0x8f, 0x5b,
    ];

    let mut out_tag = Array4x16::default();
    let actual = hmac.hmac(
        &(&Array4x16::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac512,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x16::from(result));
}

fn test_hmac1_512() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 64] = [
        0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66,
        0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65,
        0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a,
        0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65, 0x4a, 0x65, 0x66, 0x65,
        0x4a, 0x65, 0x66, 0x65,
    ];

    let data: [u8; 28] = [
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74,
        0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
    ];

    let result: [u8; 64] = [
        0xcb, 0x37, 0x09, 0x17, 0xae, 0x8a, 0x7c, 0xe2, 0x8c, 0xfd, 0x1d, 0x8f, 0x47, 0x05, 0xd6,
        0x14, 0x1c, 0x17, 0x3b, 0x2a, 0x93, 0x62, 0xc1, 0x5d, 0xf2, 0x35, 0xdf, 0xb2, 0x51, 0xb1,
        0x54, 0x54, 0x6a, 0xa3, 0x34, 0xae, 0x9f, 0xb9, 0xaf, 0xc2, 0x18, 0x49, 0x32, 0xd8, 0x69,
        0x5e, 0x39, 0x7b, 0xfa, 0x0f, 0xfb, 0x93, 0x46, 0x6c, 0xfc, 0xce, 0xaa, 0xe3, 0x8c, 0x83,
        0x3b, 0x7d, 0xba, 0x38,
    ];

    let mut out_tag = Array4x16::default();
    let actual = hmac.hmac(
        &(&Array4x16::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac512,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x16::from(result));
}

fn test_hmac2_512() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 64] = [
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa,
    ];

    let data: [u8; 50] = [
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
    ];

    let result: [u8; 64] = [
        0x2e, 0xe7, 0xac, 0xd7, 0x83, 0x62, 0x4c, 0xa9, 0x39, 0x87, 0x10, 0xf3, 0xee, 0x05, 0xae,
        0x41, 0xb9, 0xf9, 0xb0, 0x51, 0x0c, 0x87, 0xe4, 0x9e, 0x58, 0x6c, 0xc9, 0xbf, 0x96, 0x17,
        0x33, 0xd8, 0x62, 0x3c, 0x7b, 0x55, 0xce, 0xbe, 0xfc, 0xcf, 0x02, 0xd5, 0x58, 0x1a, 0xcc,
        0x1c, 0x9d, 0x5f, 0xb1, 0xff, 0x68, 0xa1, 0xde, 0x45, 0x50, 0x9f, 0xbe, 0x4d, 0xa9, 0xa4,
        0x33, 0x92, 0x26, 0x55,
    ];

    let mut out_tag = Array4x16::default();
    let actual = hmac.hmac(
        &(&Array4x16::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac512,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x16::from(result));
}

fn test_hmac3_512() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40,
    ];

    let data: [u8; 50] = [
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    ];

    let result: [u8; 64] = [
        0x5e, 0x66, 0x88, 0xe5, 0xa3, 0xda, 0xec, 0x82, 0x6c, 0xa3, 0x2e, 0xae, 0xa2, 0x24, 0xef,
        0xf5, 0xe7, 0x00, 0x62, 0x89, 0x47, 0x47, 0x0e, 0x13, 0xad, 0x01, 0x30, 0x25, 0x61, 0xba,
        0xb1, 0x08, 0xb8, 0xc4, 0x8c, 0xbc, 0x6b, 0x80, 0x7d, 0xcf, 0xbd, 0x85, 0x05, 0x21, 0xa6,
        0x85, 0xba, 0xbc, 0x7e, 0xae, 0x4a, 0x2a, 0x2e, 0x66, 0x0d, 0xc0, 0xe8, 0x6b, 0x93, 0x1d,
        0x65, 0x50, 0x3f, 0xd2,
    ];

    let mut out_tag = Array4x16::default();
    let actual = hmac.hmac(
        &(&Array4x16::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac512,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x16::from(result));
}

fn test_hmac512_multi_block() {
    let mut hmac = unsafe { Hmac::new(HmacReg::new()) };
    let mut trng = unsafe {
        Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )
        .unwrap()
    };

    let key: [u8; 64] = [
        0xe1, 0xb5, 0x2c, 0x4f, 0xf8, 0xce, 0x9c, 0x4b, 0x60, 0xbd, 0x8e, 0xc7, 0x85, 0xab, 0x7b, 0xf3,
        0xdf, 0xfc, 0x70, 0x23, 0xf7, 0xc5, 0x15, 0x88, 0xf9, 0x6b, 0x94, 0xee, 0xba, 0x80, 0xca, 0x3b,
        0x9b, 0x9e, 0xd0, 0x5a, 0xb2, 0xac, 0x87, 0x97, 0xbb, 0x70, 0x39, 0xd6, 0x81, 0xf2, 0xe4, 0x1f,
        0xcf, 0xe6, 0xdd, 0xda, 0xb2, 0xe9, 0x51, 0x22, 0xd9, 0xc7, 0x16, 0xc2, 0xb8, 0x40, 0x6b, 0xd4,
    ];

    let data: [u8; 152] = [
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75,
        0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68,
        0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65,
        0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74,
        0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64,
        0x61, 0x74, 0x61, 0x2e, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65,
        0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20,
        0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62, 0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65,
        0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c,
        0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e,
    ];

    let result : [u8; 64] = [
        0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9, 0x6e, 0x5e, 0x3f, 0xfd,
        0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86, 0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44,
        0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82, 0xb1, 0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15,
        0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60, 0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58,
    ];

    let mut out_tag = Array4x16::default();
    let actual = hmac.hmac(
        &(&Array4x16::from(key)).into(),
        &(&data).into(),
        &mut trng,
        (&mut out_tag).into(),
        HmacMode::Hmac512,
    );

    assert!(actual.is_ok());
    assert_eq!(out_tag, Array4x16::from(result));
}


// test_kat MUST be ran first.
test_suite! {
    test_kat,
    // test_hmac0,
    // test_hmac1,
    // test_hmac2,
    // test_hmac3,
    // test_hmac4,
    // test_hmac_kv_multiblock,
    // test_hmac5,
    // test_kdf0,
    // test_kdf1,
    // test_kdf2,
    // test_hmac_multi_block,
    // test_hmac_exact_single_block,
    // test_hmac_multi_block_two_step,
    // test_hmac0_512,
    // test_hmac1_512,
    // test_hmac2_512,
    // test_hmac3_512,
    test_hmac512_multi_block,
}
