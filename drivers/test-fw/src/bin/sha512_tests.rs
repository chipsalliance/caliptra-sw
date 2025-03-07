/*++

Licensed under the Apache-2.0 license.

File Name:

    sha512_tests.rs

Abstract:

    File contains test cases for SHA-512 API

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::sha2_512_384::Sha2DigestOpTrait;
use caliptra_drivers::{Array4x16, Sha2_512_384};
use caliptra_kat::Sha512Kat;
use caliptra_registers::sha512::Sha512Reg;

use caliptra_test_harness::test_suite;

fn test_digest0() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0xcf83e135, 0x7eefb8bd, 0xf1542850, 0xd66d8007, 0xd620e405, 0x0b5715dc, 0x83f4a921,
        0xd36ce9ce, 0x47d0d13c, 0x5d85f2b0, 0xff8318d2, 0x877eec2f, 0x63b931bd, 0x47417a81,
        0xa538327a, 0xf927da3e,
    ]);

    let data = &[];
    let digest = sha2.sha512_digest(data).unwrap();
    assert_eq!(digest, expected);
}

fn test_digest1() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0xddaf35a1, 0x93617aba, 0xcc417349, 0xae204131, 0x12e6fa4e, 0x89a97ea2, 0x0a9eeee6,
        0x4b55d39a, 0x2192992a, 0x274fc1a8, 0x36ba3c23, 0xa3feebbd, 0x454d4423, 0x643ce80e,
        0x2a9ac94f, 0xa54ca49f,
    ]);
    let data = "abc".as_bytes();
    let digest = sha2.sha512_digest(data.into()).unwrap();
    assert_eq!(digest, expected);
}

fn test_digest2() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0x204a8fc6, 0xdda82f0a, 0x0ced7beb, 0x8e08a416, 0x57c16ef4, 0x68b228a8, 0x279be331,
        0xa703c335, 0x96fd15c1, 0x3b1b07f9, 0xaa1d3bea, 0x57789ca0, 0x31ad85c7, 0xa71dd703,
        0x54ec6312, 0x38ca3445,
    ]);
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let digest = sha2.sha512_digest(data.into()).unwrap();
    assert_eq!(digest, expected);
}

fn test_digest3() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0x8e959b75, 0xdae313da, 0x8cf4f728, 0x14fc143f, 0x8f7779c6, 0xeb9f7fa1, 0x7299aead,
        0xb6889018, 0x501d289e, 0x4900f7e4, 0x331b99de, 0xc4b5433a, 0xc7d329ee, 0xb6dd2654,
        0x5e96e55b, 0x874be909,
    ]);
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let digest = sha2.sha512_digest(data.into()).unwrap();
    assert_eq!(digest, expected);
}

fn test_op0() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0xcf83e135, 0x7eefb8bd, 0xf1542850, 0xd66d8007, 0xd620e405, 0x0b5715dc, 0x83f4a921,
        0xd36ce9ce, 0x47d0d13c, 0x5d85f2b0, 0xff8318d2, 0x877eec2f, 0x63b931bd, 0x47417a81,
        0xa538327a, 0xf927da3e,
    ]);
    let mut digest = Array4x16::default();
    let digest_op = sha2.sha512_digest_init().unwrap();
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

fn test_op1() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };

    let expected = Array4x16::new([
        0xddaf35a1, 0x93617aba, 0xcc417349, 0xae204131, 0x12e6fa4e, 0x89a97ea2, 0x0a9eeee6,
        0x4b55d39a, 0x2192992a, 0x274fc1a8, 0x36ba3c23, 0xa3feebbd, 0x454d4423, 0x643ce80e,
        0x2a9ac94f, 0xa54ca49f,
    ]);
    let data = "abc".as_bytes();
    let mut digest = Array4x16::default();
    let mut digest_op = sha2.sha512_digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

fn test_op2() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0x204a8fc6, 0xdda82f0a, 0x0ced7beb, 0x8e08a416, 0x57c16ef4, 0x68b228a8, 0x279be331,
        0xa703c335, 0x96fd15c1, 0x3b1b07f9, 0xaa1d3bea, 0x57789ca0, 0x31ad85c7, 0xa71dd703,
        0x54ec6312, 0x38ca3445,
    ]);
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
    let mut digest = Array4x16::default();
    let mut digest_op = sha2.sha512_digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

fn test_op3() {
    let mut sha2 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };
    let expected = Array4x16::new([
        0x8e959b75, 0xdae313da, 0x8cf4f728, 0x14fc143f, 0x8f7779c6, 0xeb9f7fa1, 0x7299aead,
        0xb6889018, 0x501d289e, 0x4900f7e4, 0x331b99de, 0xc4b5433a, 0xc7d329ee, 0xb6dd2654,
        0x5e96e55b, 0x874be909,
    ]);
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let mut digest = Array4x16::default();
    let mut digest_op = sha2.sha512_digest_init().unwrap();
    assert!(digest_op.update(data).is_ok());
    let actual = digest_op.finalize(&mut digest);
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

fn test_kat() {
    // Init CFI
    CfiCounter::reset(&mut || Ok([0xDEADBEEFu32; 12]));

    let mut sha512 = unsafe { Sha2_512_384::new(Sha512Reg::new()) };

    assert!(Sha512Kat::default().execute(&mut sha512).is_ok());
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
}
