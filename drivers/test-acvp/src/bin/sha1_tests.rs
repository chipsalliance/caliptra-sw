/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_tests.rs

Abstract:

    File contains CAVP/ACVP test cases for SHA1

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::Sha1;
use caliptra_kat::Sha1Kat;
use caliptra_test_harness::{self, test_suite};

const SHA1_HASH_SIZE: usize = 20;

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(hex: &str, buf: &mut [u8]) -> Option<usize> {
    let hex = hex.as_bytes();
    if hex.len() % 2 != 0 {
        return None;
    }
    let n = hex.len() / 2;
    if n > buf.len() {
        return None;
    }
    for i in 0..n {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        buf[i] = (hi << 4) | lo;
    }
    Some(n)
}

fn test_kat() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    assert_eq!(
        Sha1Kat::default().execute(&mut Sha1::default()).is_ok(),
        true
    );
}

fn run_aft(hex_msg: &str) {
    let mut buf = [0u8; 5000];
    let len = hex_decode(hex_msg, &mut buf).unwrap();
    let digest = Sha1::default().digest(&buf[..len]).unwrap();
    let digest_out = <[u8; SHA1_HASH_SIZE]>::from(digest);
    for byte in digest_out.iter() {
        println!("SHA1:{:02X}", byte);
    }
}

fn run_mct(hex_msg: &str) {
    let mut seed = [0u8; SHA1_HASH_SIZE];
    hex_decode(hex_msg, &mut seed).unwrap();

    let mut msg = [0u8; SHA1_HASH_SIZE * 3];
    let mut digest_out = [0u8; SHA1_HASH_SIZE];

    for ol in 0..100 {
        println!("MCT ol:{}", ol);
        let mut a = seed;
        let mut b = seed;
        let mut c = seed;
        for il in 0..1000 {
            if il % 100 == 0 {
                println!("il:{}", il);
            }
            msg[0..SHA1_HASH_SIZE].copy_from_slice(&a);
            msg[SHA1_HASH_SIZE..SHA1_HASH_SIZE * 2].copy_from_slice(&b);
            msg[SHA1_HASH_SIZE * 2..SHA1_HASH_SIZE * 3].copy_from_slice(&c);
            let digest = Sha1::default().digest(&msg).unwrap();
            digest_out = <[u8; SHA1_HASH_SIZE]>::from(digest);
            a = b;
            b = c;
            c = digest_out;
        }
        for byte in digest_out.iter() {
            println!("SHA1:{:02X}", byte);
        }
        seed = digest_out;
    }
}

fn test_sha1_acvp() {
    // stimulus/current.txt is replaced before each test run with the ACVP vector.
    // Format: line 1 = test type (AFT or MCT), line 2 = hex-encoded message/seed.
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();
    let hex_msg = lines.next().unwrap().trim();
    match test_type {
        "AFT" => run_aft(hex_msg),
        "MCT" => run_mct(hex_msg),
        _ => panic!("unknown test type"),
    }
}

test_suite! {
    test_kat,
    test_sha1_acvp,
}
