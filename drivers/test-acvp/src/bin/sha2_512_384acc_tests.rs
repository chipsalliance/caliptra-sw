/*++

Licensed under the Apache-2.0 license.

File Name:

    sha2_512_384acc_tests.rs

Abstract:

    File contains ACVP test cases for the SHA-384/SHA-512 accelerator.

    Unlike the SHA-1 driver the accelerator digests data that has been placed
    in the mailbox, so each test streams the message through a mailbox
    transaction before starting the digest operation.

    The vector under test is supplied out-of-band in `stimulus/current.txt`,
    which is rewritten by the host-side runner before each invocation:

        line 1: algorithm -- "SHA384ACC" or "SHA512ACC"
        line 2: test type -- "AFT" or "MCT"
        line 3: hex-encoded message (AFT) or seed (MCT)

    Digests are reported over UART as `SHA384ACC:<hex byte>` /
    `SHA512ACC:<hex byte>` lines, one byte per line, for the runner to scrape.

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    Array4x12, Array4x16, Mailbox, Sha2_512_384Acc, ShaAccLockState, StreamEndianness,
};
use caliptra_kat::Sha2_512_384AccKat;
use caliptra_registers::mbox::MboxCsr;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use caliptra_test_harness::test_suite;

const SHA384_HASH_SIZE: usize = 48;
const SHA512_HASH_SIZE: usize = 64;

/// Largest AFT message accepted, in bytes. The 2.1 production vector sets top
/// out at 5884 bytes (11768 hex characters).
const MAX_MSG_SIZE: usize = 5900;

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
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    assert_eq!(
        Sha2_512_384AccKat::default()
            .execute(&mut sha_acc, ShaAccLockState::AssumedLocked)
            .is_ok(),
        true
    );
}

// AFT
//
// Receives an already-decoded byte slice so no &str lifetime parameter
// interferes with the MailboxSendTxn / Sha2_512_384AccOp borrow lifetimes.

fn run_aft_384(data: &[u8]) {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, data).is_ok());
        let mut digest = Array4x12::default();
        if let Some(mut op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            op.digest_384(
                data.len() as u32,
                0,
                StreamEndianness::Reorder,
                (&mut digest).into(),
            )
            .unwrap();
            drop(op);
        } else {
            assert!(false);
        }
        drop(txn);
        let digest_out = <[u8; SHA384_HASH_SIZE]>::from(digest);
        for byte in digest_out.iter() {
            println!("SHA384ACC:{:02X}", byte);
        }
    };
}

fn run_aft_512(data: &[u8]) {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, data).is_ok());
        let mut digest = Array4x16::default();
        if let Some(mut op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            op.digest_512(
                data.len() as u32,
                0,
                StreamEndianness::Reorder,
                (&mut digest).into(),
            )
            .unwrap();
            drop(op);
        } else {
            assert!(false);
        }

        drop(txn);
        let digest_out = <[u8; SHA512_HASH_SIZE]>::from(digest);
        for byte in digest_out.iter() {
            println!("SHA512ACC:{:02X}", byte);
        }
    };
}

// MCT
//
// Receives an already-decoded seed slice.

fn run_mct_384(seed_bytes: &[u8]) {
    let mut seed = [0u8; SHA384_HASH_SIZE];
    seed.copy_from_slice(seed_bytes);

    let mut msg = [0u8; SHA384_HASH_SIZE * 3];
    let mut digest_out = [0u8; SHA384_HASH_SIZE];

    for _ol in 0..100 {
        let mut a = seed;
        let mut b = seed;
        let mut c = seed;
        for _il in 0..1000 {
            msg[0..SHA384_HASH_SIZE].copy_from_slice(&a);
            msg[SHA384_HASH_SIZE..SHA384_HASH_SIZE * 2].copy_from_slice(&b);
            msg[SHA384_HASH_SIZE * 2..SHA384_HASH_SIZE * 3].copy_from_slice(&c);

            let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
            let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
            if let Some(mut txn) = mbox.try_start_send_txn() {
                const CMD: u32 = 0x1c;
                assert!(txn.send_request(CMD, &msg).is_ok());
                let mut digest = Array4x12::default();
                if let Some(mut op) = sha_acc
                    .try_start_operation(ShaAccLockState::NotAcquired)
                    .unwrap()
                {
                    op.digest_384(
                        msg.len() as u32,
                        0,
                        StreamEndianness::Reorder,
                        (&mut digest).into(),
                    )
                    .unwrap();
                    drop(op);
                } else {
                    assert!(false);
                }
                drop(txn);
                digest_out = <[u8; SHA384_HASH_SIZE]>::from(digest);
            }

            a = b;
            b = c;
            c = digest_out;
        }
        for byte in digest_out.iter() {
            println!("SHA384ACC:{:02X}", byte);
        }
        seed = digest_out;
    }
}

fn run_mct_512(seed_bytes: &[u8]) {
    let mut seed = [0u8; SHA512_HASH_SIZE];
    seed.copy_from_slice(seed_bytes);

    let mut msg = [0u8; SHA512_HASH_SIZE * 3];
    let mut digest_out = [0u8; SHA512_HASH_SIZE];

    for _ol in 0..100 {
        let mut a = seed;
        let mut b = seed;
        let mut c = seed;
        for _il in 0..1000 {
            msg[0..SHA512_HASH_SIZE].copy_from_slice(&a);
            msg[SHA512_HASH_SIZE..SHA512_HASH_SIZE * 2].copy_from_slice(&b);
            msg[SHA512_HASH_SIZE * 2..SHA512_HASH_SIZE * 3].copy_from_slice(&c);

            let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
            let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
            if let Some(mut txn) = mbox.try_start_send_txn() {
                const CMD: u32 = 0x1c;
                assert!(txn.send_request(CMD, &msg).is_ok());
                let mut digest = Array4x16::default();
                if let Some(mut op) = sha_acc
                    .try_start_operation(ShaAccLockState::NotAcquired)
                    .unwrap()
                {
                    op.digest_512(
                        msg.len() as u32,
                        0,
                        StreamEndianness::Reorder,
                        (&mut digest).into(),
                    )
                    .unwrap();
                    drop(op);
                } else {
                    assert!(false);
                }
                drop(txn);
                digest_out = <[u8; SHA512_HASH_SIZE]>::from(digest);
            }

            a = b;
            b = c;
            c = digest_out;
        }
        for byte in digest_out.iter() {
            println!("SHA512ACC:{:02X}", byte);
        }
        seed = digest_out;
    }
}

fn test_sha2_512_384acc_acvp() {
    const CURRENT: &str = include_str!("../../stimulus/current.txt");
    let mut lines = CURRENT.lines();
    let algorithm = lines.next().unwrap().trim();
    let test_type = lines.next().unwrap().trim();
    let hex_msg = lines.next().unwrap().trim();

    let mut buf = [0u8; MAX_MSG_SIZE];

    let len = match hex_decode(hex_msg, &mut buf) {
        Some(len) => len,
        None => {
            panic!(
                "hex_decode failed: hex_msg len={}, buf.len()={}",
                hex_msg.len(),
                buf.len(),
            );
        }
    };

    match (algorithm, test_type) {
        ("SHA384ACC", "AFT") => run_aft_384(&buf[..len]),
        ("SHA384ACC", "MCT") => run_mct_384(&buf[..SHA384_HASH_SIZE]),
        ("SHA512ACC", "AFT") => run_aft_512(&buf[..len]),
        ("SHA512ACC", "MCT") => run_mct_512(&buf[..SHA512_HASH_SIZE]),
        _ => panic!("unknown algorithm/test-type combination"),
    }
}

test_suite! {
    test_kat,
    test_sha2_512_384acc_acvp,
}
