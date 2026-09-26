/*++

Licensed under the Apache-2.0 license.

File Name:

    sha1_tests.rs

Abstract:

    File contains ACVP test cases for the SHA-1 driver.

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation:

        line 1: test type -- "AFT" or "MCT"
        line 2: hex-encoded message (AFT) or seed (MCT)

    Digests are reported over UART as `SHA1:<hex byte>` lines for the runner to
    scrape.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::Sha1;
use caliptra_test_harness::test_suite;

const SHA1_HASH_SIZE: usize = 20;

/// Largest AFT message accepted, in bytes.
const MAX_MSG_SIZE: usize = 5000;

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
    // Init CFI
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    assert!(Sha1::new().is_ok());
}

/// Algorithm Functional Test: digest a single message.
fn run_aft(hex_msg: &str) {
    let mut buf = [0u8; MAX_MSG_SIZE];
    let len = hex_decode(hex_msg, &mut buf).unwrap();

    let digest = Sha1::new().unwrap().digest(&buf[..len]).unwrap();

    let digest_out = <[u8; SHA1_HASH_SIZE]>::from(digest);
    for byte in digest_out.iter() {
        println!("SHA1:{:02X}", byte);
    }
}

/// Monte Carlo Test: 100 outer iterations of 1000 chained digests each.
///
/// A single `Sha1` instance is reused across all 100,000 digests. `digest()`
/// resets the compressor state on every call, so this produces the same
/// results as constructing a fresh instance each time while avoiding a
/// redundant known-answer test per iteration.
fn run_mct(hex_msg: &str) {
    let mut seed = [0u8; SHA1_HASH_SIZE];
    hex_decode(hex_msg, &mut seed).unwrap();

    let mut sha1 = Sha1::new().unwrap();
    let mut msg = [0u8; SHA1_HASH_SIZE * 3];

    for ol in 0..100 {
        println!("MCT ol:{}", ol);

        let mut a = seed;
        let mut b = seed;
        let mut c = seed;
        let mut digest_out = [0u8; SHA1_HASH_SIZE];

        for il in 0..1000 {
            if il % 100 == 0 {
                println!("il:{}", il);
            }
            msg[0..SHA1_HASH_SIZE].copy_from_slice(&a);
            msg[SHA1_HASH_SIZE..SHA1_HASH_SIZE * 2].copy_from_slice(&b);
            msg[SHA1_HASH_SIZE * 2..SHA1_HASH_SIZE * 3].copy_from_slice(&c);

            digest_out = <[u8; SHA1_HASH_SIZE]>::from(sha1.digest(&msg).unwrap());

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
