/*++

Licensed under the Apache-2.0 license.

File Name:

    sha256_tests.rs

Abstract:

    File contains test cases for SHA-256 API

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{Array4x8, Sha256, Sha256Alg, Sha256DigestOp};
use caliptra_kat::Sha256Kat;
use caliptra_registers::sha256::Sha256Reg;

use caliptra_test_harness::test_suite;

fn test_digest0() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];
    let data = [];
    let digest = sha.digest(&data).unwrap();
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_digest1() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x1, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x3, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x0,
        0x15, 0xAD,
    ];
    let data = "abc".as_bytes();
    let digest = sha.digest(data).unwrap();
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_digest2() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x6, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0xC, 0x3E, 0x60,
        0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB,
        0x6, 0xC1,
    ];
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let digest = sha.digest(data).unwrap();
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_digest3() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xCF, 0x5B, 0x16, 0xA7, 0x78, 0xAF, 0x83, 0x80, 0x3, 0x6C, 0xE5, 0x9E, 0x7B, 0x4, 0x92,
        0x37, 0xB, 0x24, 0x9B, 0x11, 0xE8, 0xF0, 0x7A, 0x51, 0xAF, 0xAC, 0x45, 0x3, 0x7A, 0xFE,
        0xE9, 0xD1,
    ];
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let digest = sha.digest(data).unwrap();
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op0() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];
    let mut digest = Array4x8::default();
    let digest_op = sha.digest_init().unwrap();
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op1() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];
    let data = [];
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    assert!(digest_op.update(&data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op2() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x1, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x3, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x0,
        0x15, 0xAD,
    ];
    let data = "abc".as_bytes();
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op3() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x6, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0xC, 0x3E, 0x60,
        0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB,
        0x6, 0xC1,
    ];
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op4() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xCF, 0x5B, 0x16, 0xA7, 0x78, 0xAF, 0x83, 0x80, 0x3, 0x6C, 0xE5, 0x9E, 0x7B, 0x4, 0x92,
        0x37, 0xB, 0x24, 0x9B, 0x11, 0xE8, 0xF0, 0x7A, 0x51, 0xAF, 0xAC, 0x45, 0x3, 0x7A, 0xFE,
        0xE9, 0xD1,
    ];
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op5() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E,
        0x67, 0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0xE, 0x4, 0x6D, 0x39, 0xCC, 0xC7, 0x11,
        0x2C, 0xD0,
    ];
    const DATA: [u8; 1000] = [0x61; 1000];
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    for _ in 0..1_000 {
        assert!(digest_op.update(&DATA).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op6() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0x06, 0xf9, 0xb1, 0xa7, 0xac, 0x97, 0xbc, 0x8e, 0x6a, 0x83, 0x5c, 0x08, 0x98, 0x6f, 0xe5,
        0x38, 0xf0, 0x47, 0x8b, 0x03, 0x82, 0x6e, 0xfb, 0x4e, 0xed, 0x35, 0xdc, 0x51, 0x7b, 0x43,
        0x3b, 0x8a,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz".as_bytes();
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op7() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0x2f, 0xcd, 0x5a, 0x0d, 0x60, 0xe4, 0xc9, 0x41, 0x38, 0x1f, 0xcc, 0x4e, 0x00, 0xa4, 0xbf,
        0x8b, 0xe4, 0x22, 0xc3, 0xdd, 0xfa, 0xfb, 0x93, 0xc8, 0x09, 0xe8, 0xd1, 0xe2, 0xbf, 0xff,
        0xae, 0x8e,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl".as_bytes();
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_op8() {
    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    let expected: [u8; 32] = [
        0x78, 0x4f, 0x62, 0x3b, 0x78, 0x74, 0x95, 0x07, 0x8e, 0x93, 0xff, 0x28, 0xa2, 0x5b, 0x58,
        0x1d, 0xf0, 0x58, 0x40, 0x55, 0xa7, 0xe7, 0x1d, 0x8c, 0xd9, 0x0c, 0x45, 0x47, 0x16, 0xb9,
        0x2f, 0x51,
    ];
    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd".as_bytes(); // Exact single block
    let mut digest = Array4x8::default();
    let mut digest_op = sha.digest_init().unwrap();
    for idx in 0..data.len() {
        assert!(digest_op.update(&data[idx..idx + 1]).is_ok());
    }
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, Array4x8::from(expected));
}

fn test_kat() {
    // Init CFI
    CfiCounter::reset(&mut || Ok([0xDEADBEEFu32; 12]));

    let mut sha = unsafe { Sha256::new(Sha256Reg::new()) };
    assert!(Sha256Kat::default().execute(&mut sha).is_ok());
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
}
