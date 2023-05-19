/*++

Licensed under the Apache-2.0 license.

File Name:

    sha384_tests.rs

Abstract:

    File contains test cases for SHA-384 Accelerator API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Array4x12, Mailbox, Sha384Acc};
use caliptra_kat::Sha384AccKat;
use caliptra_registers::mbox::MboxCsr;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use caliptra_test_harness::test_suite;

const MAX_MAILBOX_CAPACITY_BYTES: usize = 128 << 10;
const SHA384_HASH_SIZE: usize = 48;

fn test_digest0() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    let data = "abcd".as_bytes();

    let expected: [u8; SHA384_HASH_SIZE] = [
        0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54, 0x62,
        0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17, 0x1a, 0x79,
        0x5, 0xea, 0x5a, 0x2, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11, 0x5c, 0x36, 0x3a,
        0xa3, 0xc7, 0x9b,
    ];

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        let mut digest = Array4x12::default();
        if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
            let result = sha_acc_op.digest(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));
            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest1() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B,
        0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0,
        0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91,
        0x74, 0x60, 0x39,
    ];

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        let mut digest = Array4x12::default();
        if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
            let result = sha_acc_op.digest(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));
            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest2() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0x67, 0x4b, 0x2e, 0x80, 0xff, 0x8d, 0x94, 0x00, 0x8d, 0xe7, 0x40, 0x9c, 0x7b, 0x1f, 0x87,
        0x8f, 0x9f, 0xae, 0x3a, 0x0a, 0x6d, 0xae, 0x2f, 0x98, 0x2c, 0xca, 0x7e, 0x3a, 0xae, 0xf9,
        0x1b, 0xf3, 0x25, 0xd3, 0xeb, 0x56, 0x82, 0x63, 0xa2, 0xe1, 0xe6, 0x85, 0x6a, 0xc7, 0x50,
        0x70, 0x06, 0x2a,
    ];

    let mut digest = Array4x12::default();

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
            let result = sha_acc_op.digest(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));
            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest_offset() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghijklmnopqrst".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0xd4, 0xcc, 0x9a, 0x0d, 0xc5, 0x46, 0x09, 0x40, 0xb0, 0x50, 0xa2, 0x42, 0x14, 0xf6, 0x78,
        0xf6, 0x3b, 0x99, 0x3e, 0xc3, 0xc5, 0x7d, 0xb9, 0xcc, 0x20, 0x7b, 0x20, 0x9c, 0xbd, 0xa7,
        0xcc, 0x09, 0xe9, 0x4a, 0x84, 0x62, 0x83, 0x56, 0x7d, 0x28, 0xd8, 0xc7, 0x73, 0xc1, 0x87,
        0x39, 0x07, 0xa7,
    ];

    let mut digest = Array4x12::default();

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
            let result = sha_acc_op.digest(8, 4, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));
            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest_zero_size_buffer() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };

    let expected: [u8; SHA384_HASH_SIZE] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];

    let mut digest = Array4x12::default();
    if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
        let result = sha_acc_op.digest(0, 0, true, (&mut digest).into());
        assert!(result.is_ok());
        assert_eq!(digest, Array4x12::from(expected));
        drop(sha_acc_op);
    } else {
        assert!(false);
    };
}

fn test_digest_max_mailbox_size() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };

    let expected: [u8; SHA384_HASH_SIZE] = [
        0xca, 0xd1, 0x95, 0xe7, 0xc3, 0xf2, 0xb2, 0x50, 0xb3, 0x5a, 0xc7, 0x8b, 0x17, 0xb7, 0xc2,
        0xf2, 0x29, 0xe1, 0x34, 0xb8, 0x61, 0xf2, 0xd0, 0xbe, 0x15, 0xb7, 0xd9, 0x54, 0x69, 0x71,
        0xf8, 0x5e, 0xc0, 0x40, 0x69, 0x3e, 0x5a, 0x22, 0x21, 0x88, 0x79, 0x77, 0xfd, 0xea, 0x6f,
        0x89, 0xef, 0xee,
    ];

    let mut digest = Array4x12::default();
    if let Some(mut sha_acc_op) = sha_acc.try_start_operation() {
        let result = sha_acc_op.digest(
            MAX_MAILBOX_CAPACITY_BYTES as u32,
            0,
            true,
            (&mut digest).into(),
        );
        assert!(result.is_ok());
        assert_eq!(digest, Array4x12::from(expected));
        drop(sha_acc_op);
    } else {
        assert!(false);
    };
}

fn test_kat() {
    let mut sha_acc = unsafe { Sha384Acc::new(Sha512AccCsr::new()) };
    assert_eq!(Sha384AccKat::default().execute(&mut sha_acc).is_ok(), true);
}

test_suite! {
    test_kat,
    test_digest_max_mailbox_size,
    test_digest_offset,
    test_digest0,
    test_digest1,
    test_digest2,
    test_digest_zero_size_buffer,
}
