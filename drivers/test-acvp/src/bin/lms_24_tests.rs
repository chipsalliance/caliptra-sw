/*++

Licensed under the Apache-2.0 license.

File Name:

    lms_24_tests.rs

Abstract:

    File contains ACVP test cases for LMS signature verification using
    SHA256/192 (N=6, P=51, H=15).

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation:

        line 1: "LMS_SIGVER"
        line 2: hex-encoded message
        line 3: hex-encoded public key (48 bytes)
        line 4: hex-encoded signature (1620 bytes)

    The verdict is reported over UART as `LMS_SIGVER:01` for a valid signature
    or `LMS_SIGVER:00` for an invalid one.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{CaliptraError, Lms, LmsResult, Sha256};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use caliptra_registers::sha256::Sha256Reg;
use caliptra_test_harness::test_suite;
use zerocopy::FromBytes;

/// Largest message accepted, in bytes. The 2.1 production vector set tops out
/// at 128 bytes.
const MAX_MSG_SIZE: usize = 1024;

/// Serialized size of `LmsPublicKey<6>`.
const PUBKEY_SIZE: usize = 48;

/// Serialized size of `LmsSignature<6, 51, 15>`.
const SIG_SIZE: usize = 1620;

/// `DRIVER_LMS_*` occupies 0x000C_0000..=0x000C_FFFF, and every code in that
/// range describes a malformed public key or signature: a bogus algorithm
/// type, an out-of-range q, a bad path depth, and so on.
///
/// ACVP sigVer sets include such vectors deliberately - the 2.1 production set
/// has one whose signature declares LMS tree type 0x17, which does not exist -
/// and the expected answer for them is "signature invalid", not a crash. An
/// error from outside this range is an infrastructure failure and must not be
/// reported as a verification verdict.
fn is_malformed_lms_input(e: CaliptraError) -> bool {
    (0x000C_0000..=0x000C_FFFF).contains(&u32::from(e))
}

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

/// Decodes a fixed-size hex field into `buf`, panicking unless exactly
/// `expected` bytes were decoded.
///
/// `hex_decode` rejects odd-length and over-long input, but a field shorter
/// than its buffer decodes successfully and leaves the tail zeroed, which would
/// silently run the test against a value the vector never specified.
fn hex_decode_exact(hex: &str, buf: &mut [u8], expected: usize, field: &str) {
    let n = hex_decode(hex, buf).unwrap_or_else(|| {
        panic!(
            "{} is not valid hex, or is longer than {} bytes",
            field,
            buf.len()
        )
    });
    assert_eq!(
        n, expected,
        "{} must be exactly {} bytes, got {}",
        field, expected, n
    );
}

fn test_sigver_acvp() {
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let test_type = lines.next().unwrap().trim();
    let hex_msg = lines.next().unwrap().trim();
    let hex_pubkey = lines.next().unwrap().trim();
    let hex_sig = lines.next().unwrap().trim();

    assert_eq!(test_type, "LMS_SIGVER");

    let mut msg_buf = [0u8; MAX_MSG_SIZE];
    let mut pubkey_buf = [0u8; PUBKEY_SIZE];
    let mut sig_buf = [0u8; SIG_SIZE];

    let msg_len = hex_decode(hex_msg, &mut msg_buf).unwrap();
    hex_decode_exact(hex_pubkey, &mut pubkey_buf, PUBKEY_SIZE, "public key");
    hex_decode_exact(hex_sig, &mut sig_buf, SIG_SIZE, "signature");

    // Both types are `repr(C)` over zerocopy byteorder fields, so they are
    // align-1 and padding-free, and `ref_from_bytes` is sound over these buffers.
    //
    // Note it does not validate the vector: it compares against the buffer
    // length, which is PUBKEY_SIZE / SIG_SIZE by construction and so always
    // matches. A malformed field is caught by `hex_decode_exact` above.
    let lms_public_key = LmsPublicKey::<6>::ref_from_bytes(&pubkey_buf).unwrap();
    let lms_sig = LmsSignature::<6, 51, 15>::ref_from_bytes(&sig_buf).unwrap();

    let mut sha256 = unsafe { Sha256::new(Sha256Reg::new()) };

    let result = Lms::default().verify_lms_signature(
        &mut sha256,
        &msg_buf[..msg_len],
        lms_public_key,
        lms_sig,
    );

    match result {
        Ok(LmsResult::Success) => println!("LMS_SIGVER:01"),
        Ok(LmsResult::SigVerifyFailed) => println!("LMS_SIGVER:00"),

        // The driver rejects a malformed signature while parsing it, before it
        // ever gets to compare hashes, so this is still a "signature invalid"
        // verdict and not a failure to produce one.
        Err(e) if is_malformed_lms_input(e) => println!("LMS_SIGVER:00"),

        // Anything else - a SHA-256 failure, say - is an infrastructure
        // problem. Panic rather than recording it as a verdict: the runner
        // treats the non-zero exit as a failed case and omits it from the
        // response file instead of submitting a `false` we never computed.
        Err(e) => panic!("LMS verification failed with a non-LMS error: {}", e),
    }
}

test_suite! {
    test_sigver_acvp,
}
