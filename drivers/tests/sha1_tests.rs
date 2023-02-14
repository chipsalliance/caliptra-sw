/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_tests.rs

Abstract:

    File contains test cases for SHA1 API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{Array4x5, Array4xN, Sha1};

mod harness;

fn test_sha1(data: &str, expected: Array4x5) {
    let mut digest = Array4x5::default();
    let result = Sha1::default().digest(data.as_bytes(), &mut digest);
    assert!(result.is_ok());
    assert_eq!(digest, expected);
}

fn test_digest0() {
    let expected = Array4xN([0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709]);
    let data = "";
    test_sha1(data, expected);
}

fn test_digest1() {
    let expected = Array4xN([0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]);
    let data = "abc";
    test_sha1(data, expected);
}

fn test_digest2() {
    let expected = Array4xN([0x84983e44, 0x1c3bd26e, 0xbaae4aa1, 0xf95129e5, 0xe54670f1]);
    let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    test_sha1(data, expected);
}

fn test_digest3() {
    let expected = Array4xN([0xa49b2446, 0xa02c645b, 0xf419f995, 0xb6709125, 0x3a04a259]);
    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    test_sha1(data, expected);
}

fn test_op1() {
    let expected = Array4xN([0x34aa973c, 0xd4c4daa4, 0xf61eeb2b, 0xdbad2731, 0x6534016f]);
    const DATA: [u8; 1000] = [0x61; 1000];
    let mut digest = Array4x5::default();
    let mut sha = Sha1::default();
    let mut digest_op = sha.digest_init(&mut digest).unwrap();
    for _ in 0..1_000 {
        assert!(digest_op.update(&DATA).is_ok());
    }
    let actual = digest_op.finalize();
    assert!(actual.is_ok());
    assert_eq!(digest, expected);
}

test_suite! {
    test_digest0,
    test_digest1,
    test_digest2,
    test_digest3,
    test_op1,
}
