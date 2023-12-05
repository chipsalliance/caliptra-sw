/*++

Licensed under the Apache-2.0 license.

File Name:

    ecc384_tests.rs

Abstract:

    File contains test cases for ECC-384 API tests

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{
    Array4x12, Ecc384, Ecc384PrivKeyIn, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Scalar,
    Ecc384Seed, KeyId, KeyReadArgs, KeyUsage, KeyWriteArgs, Trng,
};
use caliptra_error::CaliptraError;
use caliptra_kat::Ecc384Kat;
use caliptra_registers::csrng::CsrngReg;
use caliptra_registers::ecc::EccReg;
use caliptra_registers::entropy_src::EntropySrcReg;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_registers::soc_ifc_trng::SocIfcTrngReg;
use caliptra_test_harness::test_suite;

const PRIV_KEY: [u8; 48] = [
    0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8, 0x73, 0xf2,
    0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e, 0x39, 0x4c, 0xa7, 0x84,
    0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9, 0x3e, 0xe, 0xab, 0x89, 0x46, 0xd6,
];

const PUB_KEY_X: [u8; 48] = [
    0xd7, 0xdd, 0x94, 0xe0, 0xbf, 0xfc, 0x4c, 0xad, 0xe9, 0x90, 0x2b, 0x7f, 0xdb, 0x15, 0x42, 0x60,
    0xd5, 0xec, 0x5d, 0xfd, 0x57, 0x95, 0xe, 0x83, 0x59, 0x1, 0x5a, 0x30, 0x2c, 0x8b, 0xf7, 0xbb,
    0xa7, 0xe5, 0xf6, 0xdf, 0xfc, 0x16, 0x85, 0x16, 0x2b, 0xdd, 0x35, 0xf9, 0xf5, 0xc1, 0xb0, 0xff,
];

const PUB_KEY_Y: [u8; 48] = [
    0xbb, 0x9c, 0x3a, 0x2f, 0x6, 0x1e, 0x8d, 0x70, 0x14, 0x27, 0x8d, 0xd5, 0x1e, 0x66, 0xa9, 0x18,
    0xa6, 0xb6, 0xf9, 0xf1, 0xc1, 0x93, 0x73, 0x12, 0xd4, 0xe7, 0xa9, 0x21, 0xb1, 0x8e, 0xf0, 0xf4,
    0x1f, 0xdd, 0x40, 0x1d, 0x9e, 0x77, 0x18, 0x50, 0x9f, 0x87, 0x31, 0xe9, 0xee, 0xc9, 0xc3, 0x1d,
];

const SIGNATURE_R: [u8; 48] = [
    0x93, 0x79, 0x9d, 0x55, 0x12, 0x26, 0x36, 0x28, 0x34, 0xf6, 0xf, 0x7b, 0x94, 0x52, 0x90, 0xb7,
    0xcc, 0xe6, 0xe9, 0x96, 0x1, 0xfb, 0x7e, 0xbd, 0x2, 0x6c, 0x2e, 0x3c, 0x44, 0x5d, 0x3c, 0xd9,
    0xb6, 0x50, 0x68, 0xda, 0xc0, 0xa8, 0x48, 0xbe, 0x9f, 0x5, 0x60, 0xaa, 0x75, 0x8f, 0xda, 0x27,
];

const SIGNATURE_S: [u8; 48] = [
    0xe5, 0x48, 0xe5, 0x35, 0xa1, 0xcc, 0x60, 0xe, 0x13, 0x3b, 0x55, 0x91, 0xae, 0xba, 0xad, 0x78,
    0x5, 0x40, 0x6, 0xd7, 0x52, 0xd0, 0xe1, 0xdf, 0x94, 0xfb, 0xfa, 0x95, 0xd7, 0x8f, 0xb, 0x3f,
    0x8e, 0x81, 0xb9, 0x11, 0x9c, 0x2b, 0xe0, 0x8, 0xbf, 0x6d, 0x6f, 0x4e, 0x41, 0x85, 0xf8, 0x7d,
];

fn test_gen_key_pair() {
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
    let seed = [0u8; 48];
    let mut priv_key = Array4x12::default();
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(&mut priv_key),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(priv_key, Ecc384Scalar::from(PRIV_KEY));
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    let mut der = [0u8; 97];
    der[0] = 0x04;
    der[01..49].copy_from_slice(&PUB_KEY_X);
    der[49..97].copy_from_slice(&PUB_KEY_Y);
    assert_eq!(pub_key.to_der(), der);
}

fn test_gen_key_pair_with_iv() {
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
    let seed = [
        0x8F, 0xA8, 0x54, 0x1C, 0x82, 0xA3, 0x92, 0xCA, 0x74, 0xF2, 0x3E, 0xD1, 0xDB, 0xFD, 0x73,
        0x54, 0x1C, 0x59, 0x66, 0x39, 0x1B, 0x97, 0xEA, 0x73, 0xD7, 0x44, 0xB0, 0xE3, 0x4B, 0x9D,
        0xF5, 0x9E, 0xD0, 0x15, 0x80, 0x63, 0xE3, 0x9C, 0x09, 0xA5, 0xA0, 0x55, 0x37, 0x1E, 0xDF,
        0x7A, 0x54, 0x41,
    ];

    let nonce = [
        0x1B, 0x7E, 0xC5, 0xE5, 0x48, 0xE8, 0xAA, 0xA9, 0x2E, 0xC7, 0x70, 0x97, 0xCA, 0x95, 0x51,
        0xC9, 0x78, 0x3C, 0xE6, 0x82, 0xCA, 0x18, 0xFB, 0x1E, 0xDB, 0xD9, 0xF1, 0xE5, 0x0B, 0xC3,
        0x82, 0xDB, 0x8A, 0xB3, 0x94, 0x96, 0xC8, 0xEE, 0x42, 0x3F, 0x8C, 0xA1, 0x05, 0xCB, 0xBA,
        0x7B, 0x65, 0x88,
    ];

    let priv_key_exp = [
        0xF2, 0x74, 0xF6, 0x9D, 0x16, 0x3B, 0x0C, 0x9F, 0x1F, 0xC3, 0xEB, 0xF4, 0x29, 0x2A, 0xD1,
        0xC4, 0xEB, 0x3C, 0xEC, 0x1C, 0x5A, 0x7D, 0xDE, 0x6F, 0x80, 0xC1, 0x42, 0x92, 0x93, 0x4C,
        0x20, 0x55, 0xE0, 0x87, 0x74, 0x8D, 0x0A, 0x16, 0x9C, 0x77, 0x24, 0x83, 0xAD, 0xEE, 0x5E,
        0xE7, 0x0E, 0x17,
    ];
    let pub_key_x_exp = [
        0xD7, 0x9C, 0x6D, 0x97, 0x2B, 0x34, 0xA1, 0xDF, 0xC9, 0x16, 0xA7, 0xB6, 0xE0, 0xA9, 0x9B,
        0x6B, 0x53, 0x87, 0xB3, 0x4D, 0xA2, 0x18, 0x76, 0x07, 0xC1, 0xAD, 0x0A, 0x4D, 0x1A, 0x8C,
        0x2E, 0x41, 0x72, 0xAB, 0x5F, 0xA5, 0xD9, 0xAB, 0x58, 0xFE, 0x45, 0xE4, 0x3F, 0x56, 0xBB,
        0xB6, 0x6B, 0xA4,
    ];
    let pub_key_y_exp = [
        0x5A, 0x73, 0x63, 0x93, 0x2B, 0x06, 0xB4, 0xF2, 0x23, 0xBE, 0xF0, 0xB6, 0x0A, 0x63, 0x90,
        0x26, 0x51, 0x12, 0xDB, 0xBD, 0x0A, 0xAE, 0x67, 0xFE, 0xF2, 0x6B, 0x46, 0x5B, 0xE9, 0x35,
        0xB4, 0x8E, 0x45, 0x1E, 0x68, 0xD1, 0x6F, 0x11, 0x18, 0xF2, 0xB3, 0x2B, 0x4C, 0x28, 0x60,
        0x87, 0x49, 0xED,
    ];

    let mut priv_key = Array4x12::default();
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::from(nonce),
        &mut trng,
        Ecc384PrivKeyOut::from(&mut priv_key),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(priv_key, Ecc384Scalar::from(priv_key_exp));
    assert_eq!(pub_key.x, Ecc384Scalar::from(pub_key_x_exp));
    assert_eq!(pub_key.y, Ecc384Scalar::from(pub_key_y_exp));
}

fn test_sign() {
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
    let digest = Array4x12::new([0u32; 12]);
    let result = ecc.sign(
        &Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        &Ecc384PubKey {
            x: Ecc384Scalar::from(PUB_KEY_X),
            y: Ecc384Scalar::from(PUB_KEY_Y),
        },
        &digest,
        &mut trng,
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(SIGNATURE_R));
    assert_eq!(signature.s, Ecc384Scalar::from(SIGNATURE_S));
}

fn test_verify() {
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
    let digest = Array4x12::new([0u32; 12]);
    let result = ecc.sign(
        &Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        &Ecc384PubKey {
            x: Ecc384Scalar::from(PUB_KEY_X),
            y: Ecc384Scalar::from(PUB_KEY_Y),
        },
        &digest,
        &mut trng,
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(PUB_KEY_X),
        y: Ecc384Scalar::from(PUB_KEY_Y),
    };
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(digest), &signature);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Ecc384Result::Success);
}

fn test_verify_r() {
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
    let digest = Array4x12::new([0u32; 12]);
    let result = ecc.sign(
        &Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        &Ecc384PubKey {
            x: Ecc384Scalar::from(PUB_KEY_X),
            y: Ecc384Scalar::from(PUB_KEY_Y),
        },
        &digest,
        &mut trng,
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(PUB_KEY_X),
        y: Ecc384Scalar::from(PUB_KEY_Y),
    };
    let result = ecc.verify_r(&pub_key, &Ecc384Scalar::from(digest), &signature);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), signature.r);
}

fn test_verify_failure() {
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
    let digest = Array4x12::new([0u32; 12]);
    let result = ecc.sign(
        &Ecc384PrivKeyIn::from(&Array4x12::from(PRIV_KEY)),
        &Ecc384PubKey {
            x: Ecc384Scalar::from(PUB_KEY_X),
            y: Ecc384Scalar::from(PUB_KEY_Y),
        },
        &digest,
        &mut trng,
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    let pub_key = Ecc384PubKey {
        x: Ecc384Scalar::from(PUB_KEY_X),
        y: Ecc384Scalar::from(PUB_KEY_Y),
    };
    let hash = [0xFFu8; 48];
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(hash), &signature);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Ecc384Result::SigVerifyFailed);
}

fn test_kv_seed_from_input_msg_from_input() {
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
    // Step 1: Generate a key pair and store private key in kv slot 2.
    //
    let seed = [0u8; 48];
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId2,
        usage: KeyUsage::default().set_ecc_private_key_en(),
    };
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    //
    // Step 2: Sign message with private key generated in step 1.
    //
    let digest = Array4x12::new([0u32; 12]);
    let key_in_1 = KeyReadArgs::new(KeyId::KeyId2);

    let result = ecc.sign(&key_in_1.into(), &pub_key, &digest, &mut trng);
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(SIGNATURE_R));
    assert_eq!(signature.s, Ecc384Scalar::from(SIGNATURE_S));

    //
    // Step 3: Verify the signature generated in step 2.
    //
    let pub_key = Ecc384PubKey {
        x: pub_key.x,
        y: pub_key.y,
    };
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(digest), &signature);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Ecc384Result::Success);
}

fn test_kv_seed_from_kv_msg_from_input() {
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
    // Step 1: Generate a key-pair. Store private key in kv slot 0.
    // Mark the key as ecc_key_gen_seed as it will be used as a seed for key generation.
    //
    // Seed generated should be:
    // [0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8, 0x73,
    //  0xf2, 0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e, 0x39, 0x4c,
    //  0xa7, 0x84, 0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9, 0x3e, 0xe, 0xab,
    //  0x89, 0x46, 0xd6,]
    //
    let seed = [0u8; 48];
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId0,
        usage: KeyUsage::default()
            .set_ecc_key_gen_seed_en()
            .set_ecc_private_key_en(),
    };
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(PUB_KEY_X));
    assert_eq!(pub_key.y, Ecc384Scalar::from(PUB_KEY_Y));

    //
    // Step 2: Generate a key pair and store private key in kv slot 1.
    // Use seed generated in step 1.
    //
    // Private key generated should be:
    // [0xc3, 0xb, 0x13, 0xa9, 0x33, 0x39, 0xbb, 0x5a, 0x2f, 0x4c, 0xed, 0xf8, 0x83, 0x57, 0x43,
    //  0x45, 0xbd, 0xa1, 0xd7, 0x7f, 0x36, 0x59, 0x75, 0x81, 0x2d, 0xa2, 0xc1, 0x4, 0xac, 0x76,
    //  0x28, 0xba, 0x9a, 0x8e, 0xf4, 0x37, 0xd0, 0x50, 0x6, 0x96, 0xc9, 0x40, 0xc, 0x20, 0x59, 0x42, 0xa5, 0x2c, ]
    //
    let pub_key_x: [u8; 48] = [
        0x93, 0x79, 0x9d, 0x55, 0x12, 0x26, 0x36, 0x28, 0x34, 0xf6, 0xf, 0x7b, 0x94, 0x52, 0x90,
        0xb7, 0xcc, 0xe6, 0xe9, 0x96, 0x1, 0xfb, 0x7e, 0xbd, 0x2, 0x6c, 0x2e, 0x3c, 0x44, 0x5d,
        0x3c, 0xd9, 0xb6, 0x50, 0x68, 0xda, 0xc0, 0xa8, 0x48, 0xbe, 0x9f, 0x5, 0x60, 0xaa, 0x75,
        0x8f, 0xda, 0x27,
    ];

    let pub_key_y: [u8; 48] = [
        0xe5, 0x87, 0xb2, 0xcd, 0x38, 0xe9, 0x4f, 0x7a, 0x2f, 0xd4, 0x31, 0xf5, 0xb1, 0xb2, 0xa8,
        0xa0, 0x33, 0x7b, 0x97, 0x63, 0x75, 0x19, 0xf4, 0xb1, 0x51, 0x3e, 0xc9, 0x0, 0x9f, 0x96,
        0x26, 0xfe, 0xb2, 0x5, 0x74, 0xfb, 0xff, 0x22, 0x5, 0xad, 0x84, 0x69, 0x87, 0xfd, 0xb6,
        0x67, 0x1d, 0x8f,
    ];
    let key_in_seed = KeyReadArgs::new(KeyId::KeyId0);
    let key_out_priv_key = KeyWriteArgs {
        id: KeyId::KeyId1,
        usage: KeyUsage::default().set_ecc_private_key_en(),
    };
    let result = ecc.key_pair(
        &Ecc384Seed::from(key_in_seed),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(key_out_priv_key),
    );
    assert!(result.is_ok());
    let pub_key = result.unwrap();
    assert_eq!(pub_key.x, Ecc384Scalar::from(pub_key_x));
    assert_eq!(pub_key.y, Ecc384Scalar::from(pub_key_y));

    //
    // Step 3: Sign message with private key generated in step 2.
    //
    // Private key is:
    // [0xc3, 0xb, 0x13, 0xa9, 0x33, 0x39, 0xbb, 0x5a, 0x2f, 0x4c, 0xed, 0xf8, 0x83, 0x57, 0x43,
    //  0x45, 0xbd, 0xa1, 0xd7, 0x7f, 0x36, 0x59, 0x75, 0x81, 0x2d, 0xa2, 0xc1, 0x4, 0xac, 0x76,
    //  0x28, 0xba, 0x9a, 0x8e, 0xf4, 0x37, 0xd0, 0x50, 0x6, 0x96, 0xc9, 0x40, 0xc, 0x20, 0x59, 0x42, 0xa5, 0x2c, ]

    let msg: [u8; 48] = [
        0xfe, 0xee, 0xf5, 0x54, 0x4a, 0x76, 0x56, 0x49, 0x90, 0x12, 0x8a, 0xd1, 0x89, 0xe8, 0x73,
        0xf2, 0x1f, 0xd, 0xfd, 0x5a, 0xd7, 0xe2, 0xfa, 0x86, 0x11, 0x27, 0xee, 0x6e, 0x39, 0x4c,
        0xa7, 0x84, 0x87, 0x1c, 0x1a, 0xec, 0x3, 0x2c, 0x7a, 0x8b, 0x10, 0xb9, 0x3e, 0xe, 0xab,
        0x89, 0x46, 0xd6,
    ];
    let sig_r: [u8; 48] = [
        0xda, 0x48, 0xb4, 0xc1, 0x6a, 0xed, 0x87, 0x69, 0xc0, 0x64, 0x48, 0x3d, 0x4b, 0xc8, 0xba,
        0xb3, 0xe, 0x4a, 0x51, 0x3d, 0x45, 0x80, 0x5d, 0x18, 0x73, 0x89, 0x42, 0x46, 0xe4, 0xd5,
        0xd6, 0x1, 0x83, 0xd8, 0x41, 0xaf, 0xbf, 0xaa, 0xc2, 0x57, 0xff, 0xc, 0xff, 0x20, 0xbf,
        0x65, 0x8c, 0xa4,
    ];
    let sig_s: [u8; 48] = [
        0xdd, 0xb4, 0xbd, 0x4c, 0xbf, 0x7c, 0xa5, 0x2e, 0xd0, 0xea, 0xdc, 0xbe, 0x7c, 0x42, 0xbe,
        0x99, 0x9d, 0x97, 0x14, 0xbe, 0x15, 0xa8, 0x8b, 0x45, 0x67, 0x18, 0x15, 0x46, 0x85, 0x7d,
        0xa0, 0xb3, 0x49, 0xe8, 0x90, 0x28, 0x45, 0x74, 0xb7, 0x2e, 0x42, 0xd3, 0xa1, 0x38, 0xdc,
        0xe8, 0x8c, 0x10,
    ];
    let key_in_priv_key = KeyReadArgs::new(KeyId::KeyId1);
    let result = ecc.sign(
        &key_in_priv_key.into(),
        &pub_key,
        &Array4x12::from(msg),
        &mut trng,
    );
    assert!(result.is_ok());
    let signature = result.unwrap();
    assert_eq!(signature.r, Ecc384Scalar::from(sig_r));
    assert_eq!(signature.s, Ecc384Scalar::from(sig_s));

    //
    // Step 4: Verify the signature generated in step 2.
    //
    let pub_key = Ecc384PubKey {
        x: pub_key_x.into(),
        y: pub_key_y.into(),
    };
    let result = ecc.verify(&pub_key, &Ecc384Scalar::from(msg), &signature);
    assert_eq!(result.unwrap(), Ecc384Result::Success);
}

fn test_no_private_key_usage() {
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
    let seed = [0u8; 48];
    let key_out_1 = KeyWriteArgs {
        id: KeyId::KeyId0,
        // The caller needs to use set_ecc_private_key_en() here to prevent the error
        usage: KeyUsage::default().set_ecc_key_gen_seed_en(),
    };
    let result = ecc.key_pair(
        &Ecc384Seed::from(&Ecc384Scalar::from(seed)),
        &Array4x12::default(),
        &mut trng,
        Ecc384PrivKeyOut::from(key_out_1),
    );
    assert_eq!(result, Err(CaliptraError::DRIVER_ECC384_KEYGEN_BAD_USAGE))
}

fn test_kat() {
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

    // Init CFI
    let mut entropy_gen = || trng.generate().map(|a| a.0);
    CfiCounter::reset(&mut entropy_gen);

    assert_eq!(
        Ecc384Kat::default().execute(&mut ecc, &mut trng).is_ok(),
        true
    );
}

test_suite! {
    test_kat,
    test_gen_key_pair,
    test_gen_key_pair_with_iv,
    test_sign,
    test_verify,
    test_verify_r,
    test_verify_failure,
    test_kv_seed_from_input_msg_from_input,
    test_kv_seed_from_kv_msg_from_input,
    test_no_private_key_usage,
}
