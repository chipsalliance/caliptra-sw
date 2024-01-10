/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384_tests.rs

Abstract:

    File contains test cases for SHA-384 API

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{Array4x12, PcrBank, PcrId, Sha384};
use caliptra_kat::Sha384Kat;
use caliptra_registers::{pv::PvReg, sha512::Sha512Reg};

use caliptra_test_harness::test_suite;

fn test_digest0() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];

    // Why does this break extending PCR on FPGA??
    let _ = sha384.gen_pcr_hash([0; 32].into());

    let data = &[];
    let digest = sha384.digest(data).unwrap();
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_digest1() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50,
        0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF,
        0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34,
        0xC8, 0x25, 0xA7,
    ];
    let data = "abc".as_bytes();
    let digest = sha384.digest(data.into()).unwrap();
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_digest2() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39, 0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47, 0x09,
        0x39, 0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB, 0xFE, 0x8F, 0x45, 0x0D, 0xE5, 0xF3,
        0x6B, 0xC6, 0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F, 0x5F, 0xE9, 0x5B, 0x1F, 0xE3,
        0xC8, 0x45, 0x2B,
    ];
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let digest = sha384.digest(data.into()).unwrap();
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_digest3() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B,
        0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0,
        0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91,
        0x74, 0x60, 0x39,
    ];
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let digest = sha384.digest(data.into()).unwrap();
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op0() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];
    let mut digest = Array4x12::default();
    let digest_op = sha384.digest_init().unwrap();
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op1() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];
    let mut digest = Array4x12::default();
    let digest_op = sha384.digest_init().unwrap();
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op2() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0xCB, 0x00, 0x75, 0x3F, 0x45, 0xA3, 0x5E, 0x8B, 0xB5, 0xA0, 0x3D, 0x69, 0x9A, 0xC6, 0x50,
        0x07, 0x27, 0x2C, 0x32, 0xAB, 0x0E, 0xDE, 0xD1, 0x63, 0x1A, 0x8B, 0x60, 0x5A, 0x43, 0xFF,
        0x5B, 0xED, 0x80, 0x86, 0x07, 0x2B, 0xA1, 0xE7, 0xCC, 0x23, 0x58, 0xBA, 0xEC, 0xA1, 0x34,
        0xC8, 0x25, 0xA7,
    ];

    let data = "abc".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op3() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x33, 0x91, 0xFD, 0xDD, 0xFC, 0x8D, 0xC7, 0x39, 0x37, 0x07, 0xA6, 0x5B, 0x1B, 0x47, 0x09,
        0x39, 0x7C, 0xF8, 0xB1, 0xD1, 0x62, 0xAF, 0x05, 0xAB, 0xFE, 0x8F, 0x45, 0x0D, 0xE5, 0xF3,
        0x6B, 0xC6, 0xB0, 0x45, 0x5A, 0x85, 0x20, 0xBC, 0x4E, 0x6F, 0x5F, 0xE9, 0x5B, 0x1F, 0xE3,
        0xC8, 0x45, 0x2B,
    ];
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op4() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B,
        0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0,
        0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91,
        0x74, 0x60, 0x39,
    ];
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op5() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x9D, 0x0E, 0x18, 0x09, 0x71, 0x64, 0x74, 0xCB, 0x08, 0x6E, 0x83, 0x4E, 0x31, 0x0A, 0x4A,
        0x1C, 0xED, 0x14, 0x9E, 0x9C, 0x00, 0xF2, 0x48, 0x52, 0x79, 0x72, 0xCE, 0xC5, 0x70, 0x4C,
        0x2A, 0x5B, 0x07, 0xB8, 0xB3, 0xDC, 0x38, 0xEC, 0xC4, 0xEB, 0xAE, 0x97, 0xDD, 0xD8, 0x7F,
        0x3D, 0x89, 0x85,
    ];
    const DATA: [u8; 1000] = [0x61; 1000];
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    for _ in 0..1_000 {
        assert!(digest_op.update(&DATA).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op6() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb, 0xaa,
        0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29, 0xbd, 0xb6,
        0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7, 0xa3, 0x59, 0x14,
        0xfc, 0x1e, 0xcd,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op7() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x67, 0x4b, 0x2e, 0x80, 0xff, 0x8d, 0x94, 0x00, 0x8d, 0xe7, 0x40, 0x9c, 0x7b, 0x1f, 0x87,
        0x8f, 0x9f, 0xae, 0x3a, 0x0a, 0x6d, 0xae, 0x2f, 0x98, 0x2c, 0xca, 0x7e, 0x3a, 0xae, 0xf9,
        0x1b, 0xf3, 0x25, 0xd3, 0xeb, 0x56, 0x82, 0x63, 0xa2, 0xe1, 0xe6, 0x85, 0x6a, 0xc7, 0x50,
        0x70, 0x06, 0x2a,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_op8() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let expected: [u8; 48] = [
        0x55, 0x23, 0xcf, 0xb7, 0x7f, 0x9c, 0x55, 0xe0, 0xcc, 0xaf, 0xec, 0x5b, 0x87, 0xd7, 0x9c,
        0xde, 0x64, 0x30, 0x12, 0x28, 0x3b, 0x71, 0x18, 0x8e, 0x40, 0x8c, 0x5a, 0xea, 0xe9, 0x19,
        0xa3, 0xf2, 0x93, 0x37, 0x57, 0x4d, 0x5c, 0x72, 0x9b, 0x33, 0x9d, 0x95, 0x53, 0x98, 0x4a,
        0xb0, 0x01, 0x4e,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh".as_bytes();
    let mut digest = Array4x12::default();
    let mut digest_op = sha384.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x12::from(expected));
}

fn test_pcr_hash_extend_single_block() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    // fn change_endianess(arr: mut &[u8]) {
    //     for idx in (0..self.len()).step_by(4) {
    //         self.swap(idx, idx + 3);
    //         self.swap(idx + 1, idx + 2);
    //     }
    // }

    let expected_round_1: [u8; 48] = [
        0x4d, 0xca, 0xf1, 0x2f, 0xab, 0xaa, 0x55, 0x47, 0xf4, 0x6c, 0x32, 0x64, 0xb1, 0xe4, 0x5b,
        0xc4, 0x5, 0x5c, 0x0, 0xe, 0x66, 0x2c, 0x6c, 0x8a, 0x2c, 0xca, 0x71, 0x2b, 0x44, 0x2d,
        0x82, 0x6a, 0xf0, 0xbc, 0x35, 0x96, 0x2b, 0x59, 0x45, 0x17, 0xb3, 0x2f, 0xe1, 0x66, 0x73,
        0xd1, 0x20, 0x30,
    ];
    let expected_round_2: [u8; 48] = [
        0xe0, 0x4, 0x44, 0x8, 0xb7, 0x28, 0xe8, 0xcc, 0x18, 0x76, 0x1e, 0x30, 0xde, 0x50, 0xb0,
        0xa5, 0x30, 0xd7, 0xfa, 0x58, 0x78, 0x62, 0x8, 0xc2, 0xb1, 0x75, 0xa9, 0x7c, 0x6c, 0x25,
        0x50, 0x50, 0x4, 0x4c, 0x6c, 0x2f, 0xcf, 0xc6, 0x40, 0x46, 0xcc, 0xea, 0x1c, 0x3a, 0xe1,
        0x2e, 0xe6, 0x72,
    ];
    let data: [u8; 48] = [
        0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb, 0xaa,
        0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29, 0xbd, 0xb6,
        0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7, 0xa3, 0x59, 0x14,
        0xfc, 0x1e, 0xcd,
    ];
    pcr_bank.erase_all_pcrs();

    // Why does this break extending PCR on FPGA??
    let _ = sha384.gen_pcr_hash([0; 32].into());

    // Round 1: PCR is all zeros.
    let result = sha384.pcr_extend(PcrId::PcrId0, &data);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_1)
    );

    // Round 2: PCR is expected_round_1
    let result = sha384.pcr_extend(PcrId::PcrId0, &data);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_2)
    );
}

fn test_pcr_hash_extend_single_block_2() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    let expected_round_1: [u8; 48] = [
        0x4d, 0xca, 0xf1, 0x2f, 0xab, 0xaa, 0x55, 0x47, 0xf4, 0x6c, 0x32, 0x64, 0xb1, 0xe4, 0x5b,
        0xc4, 0x5, 0x5c, 0x0, 0xe, 0x66, 0x2c, 0x6c, 0x8a, 0x2c, 0xca, 0x71, 0x2b, 0x44, 0x2d,
        0x82, 0x6a, 0xf0, 0xbc, 0x35, 0x96, 0x2b, 0x59, 0x45, 0x17, 0xb3, 0x2f, 0xe1, 0x66, 0x73,
        0xd1, 0x20, 0x30,
    ];
    let expected_round_2: [u8; 48] = [
        0x13, 0xc4, 0x1e, 0x3a, 0xd2, 0x7f, 0x9d, 0xaa, 0xdb, 0x92, 0x8f, 0x25, 0x9d, 0x35, 0xf9,
        0xd1, 0x3d, 0xeb, 0x13, 0x39, 0x73, 0x2, 0x19, 0x21, 0x98, 0x7b, 0x32, 0x2b, 0xb6, 0xd4,
        0xfa, 0xb0, 0xcc, 0x4f, 0xae, 0xfa, 0x43, 0xf1, 0xf7, 0x12, 0x1e, 0x66, 0x99, 0x7a, 0xb5,
        0xdf, 0xa0, 0x3d,
    ];
    let data: [u8; 48] = [
        0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb, 0xaa,
        0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29, 0xbd, 0xb6,
        0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7, 0xa3, 0x59, 0x14,
        0xfc, 0x1e, 0xcd,
    ];
    pcr_bank.erase_all_pcrs();

    // Round 1: PCR is all zeros.
    let result = sha384.pcr_extend(PcrId::PcrId0, &data);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_1)
    );

    // Round 2: PCR is expected_round_1
    let result = sha384.pcr_extend(PcrId::PcrId0, &[]);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_2)
    );
}

fn test_pcr_hash_extend_single_block_3() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    let expected_round_1: [u8; 48] = [
        0x4d, 0xca, 0xf1, 0x2f, 0xab, 0xaa, 0x55, 0x47, 0xf4, 0x6c, 0x32, 0x64, 0xb1, 0xe4, 0x5b,
        0xc4, 0x5, 0x5c, 0x0, 0xe, 0x66, 0x2c, 0x6c, 0x8a, 0x2c, 0xca, 0x71, 0x2b, 0x44, 0x2d,
        0x82, 0x6a, 0xf0, 0xbc, 0x35, 0x96, 0x2b, 0x59, 0x45, 0x17, 0xb3, 0x2f, 0xe1, 0x66, 0x73,
        0xd1, 0x20, 0x30,
    ];
    let expected_round_2: [u8; 48] = [
        0xa1, 0xaa, 0x37, 0xde, 0x2b, 0x9f, 0x9e, 0x93, 0xac, 0xd4, 0x38, 0xbb, 0x2b, 0x80, 0xf4,
        0xf4, 0x88, 0x5f, 0x6b, 0x96, 0xef, 0x2f, 0xe8, 0x74, 0xd8, 0x2f, 0x46, 0x77, 0x65, 0x35,
        0x7, 0x66, 0x34, 0x1a, 0x62, 0x43, 0xf4, 0xaa, 0x72, 0x26, 0x4f, 0x10, 0xe0, 0xa5, 0x1b,
        0x77, 0xae, 0xc3,
    ];
    let data: [u8; 48] = [
        0x9c, 0x2f, 0x48, 0x76, 0x0d, 0x13, 0xac, 0x42, 0xea, 0xd1, 0x96, 0xe5, 0x4d, 0xcb, 0xaa,
        0x5e, 0x58, 0x72, 0x06, 0x62, 0xa9, 0x6b, 0x91, 0x94, 0xe9, 0x81, 0x33, 0x29, 0xbd, 0xb6,
        0x27, 0xc7, 0xc1, 0xca, 0x77, 0x15, 0x31, 0x16, 0x32, 0xc1, 0x39, 0xe7, 0xa3, 0x59, 0x14,
        0xfc, 0x1e, 0xcd,
    ];
    let extended_data: [u8; 1] = [0xa];

    pcr_bank.erase_all_pcrs();

    // Round 1: PCR is all zeros.
    let result = sha384.pcr_extend(PcrId::PcrId0, &data);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_1)
    );

    // Round 2: PCR is expected_round_1
    let result = sha384.pcr_extend(PcrId::PcrId0, &extended_data);
    assert!(result.is_ok());
    assert_eq!(
        pcr_bank.read_pcr(PcrId::PcrId0),
        Array4x12::from(expected_round_2)
    );
}

fn test_pcr_hash_extend_limit() {
    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };

    let data_allowed: [u8; 79] = [0u8; 79];
    let data_not_allowed: [u8; 80] = [0u8; 80];

    let result = sha384.pcr_extend(PcrId::PcrId0, &data_allowed);
    assert!(result.is_ok());
    let result = sha384.pcr_extend(PcrId::PcrId0, &data_not_allowed);
    assert!(result.is_err());
}

fn test_kat() {
    // Init CFI
    CfiCounter::reset(&mut || Ok([0xDEADBEEFu32; 12]));

    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };

    assert_eq!(Sha384Kat::default().execute(&mut sha384).is_ok(), true);
}

test_suite! {
    test_kat,
    test_digest0,
    test_digest1,
    test_digest2,
    test_digest3,
    test_op0,
    test_op1,
    test_op2,
    test_op3,
    test_op4,
    test_op5,
    test_op6,
    test_op7,
    test_op8,
    test_pcr_hash_extend_single_block,
    test_pcr_hash_extend_single_block_2,
    test_pcr_hash_extend_single_block_3,
    test_pcr_hash_extend_limit,
}
