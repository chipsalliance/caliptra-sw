/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_24_tests.rs

Abstract:

    File contains ACVP test cases for LMS signature verification using SHA256/192.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Lms, LmsResult, Sha256};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::{self, test_suite};

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

fn test_sigver_acvp() {
    // stimulus/current.txt format (four lines):
    //   line 1: "LMS_SIGVER"
    //   line 2: hex-encoded message
    //   line 3: hex-encoded public key (48 bytes)
    //   line 4: hex-encoded signature
    println!("Start ACVP test");
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();
    let hex_msg = lines.next().unwrap().trim();
    let hex_pubkey = lines.next().unwrap().trim();
    let hex_sig = lines.next().unwrap().trim();

    assert_eq!(test_type, "LMS_SIGVER");

    let mut msg_buf = [0u8; 1024];
    let mut pubkey_buf = [0u8; 48];
    let mut sig_buf = [0u8; 1620];

    let msg_len = hex_decode(hex_msg, &mut msg_buf).unwrap();
    hex_decode(hex_pubkey, &mut pubkey_buf).unwrap();
    hex_decode(hex_sig, &mut sig_buf).unwrap();

    let lms_public_key: &LmsPublicKey<6> =
        unsafe { &*(pubkey_buf.as_ptr() as *const LmsPublicKey<6>) };
    let lms_sig: &LmsSignature<6, 51, 15> =
        unsafe { &*(sig_buf.as_ptr() as *const LmsSignature<6, 51, 15>) };

    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };

    let result = Lms::default()
        .verify_lms_signature(&mut sha256, &msg_buf[..msg_len], lms_public_key, lms_sig);

    match result {
        Ok(LmsResult::Success) => println!("LMS_SIGVER:01"),
        _ => println!("LMS_SIGVER:00"),
    }
}

test_suite! {
    test_sigver_acvp,
}
