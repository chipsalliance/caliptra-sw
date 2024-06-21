/*++

Licensed under the Apache-2.0 license.

File Name:

    sha2_512_384_tests.rs

Abstract:

    File contains test cases for SHA-384 Accelerator API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    memory_layout, Array4x12, Array4x16, Mailbox, Sha2_512_384Acc, ShaAccLockState,
};
use caliptra_kat::Sha2_512_384AccKat;
use caliptra_registers::mbox::MboxCsr;
use caliptra_registers::sha512_acc::Sha512AccCsr;
use caliptra_test_harness::test_suite;
use core::slice;

const MAX_MAILBOX_CAPACITY_BYTES: usize = 128 << 10;
const SHA384_HASH_SIZE: usize = 48;
const SHA512_HASH_SIZE: usize = 64;

fn test_digest0() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    let data = "abcd".as_bytes();

    let expected: [u8; SHA384_HASH_SIZE] = [
        0x11, 0x65, 0xb3, 0x40, 0x6f, 0xf0, 0xb5, 0x2a, 0x3d, 0x24, 0x72, 0x1f, 0x78, 0x54, 0x62,
        0xca, 0x22, 0x76, 0xc9, 0xf4, 0x54, 0xa1, 0x16, 0xc2, 0xb2, 0xba, 0x20, 0x17, 0x1a, 0x79,
        0x5, 0xea, 0x5a, 0x2, 0x66, 0x82, 0xeb, 0x65, 0x9c, 0x4d, 0x5f, 0x11, 0x5c, 0x36, 0x3a,
        0xa3, 0xc7, 0x9b,
    ];

    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0xd8, 0x02, 0x2f, 0x20, 0x60, 0xad, 0x6e, 0xfd, 0x29, 0x7a, 0xb7, 0x3d, 0xcc, 0x53, 0x55,
        0xc9, 0xb2, 0x14, 0x05, 0x4b, 0x0d, 0x17, 0x76, 0xa1, 0x36, 0xa6, 0x69, 0xd2, 0x6a, 0x7d,
        0x3b, 0x14, 0xf7, 0x3a, 0xa0, 0xd0, 0xeb, 0xff, 0x19, 0xee, 0x33, 0x33, 0x68, 0xf0, 0x16,
        0x4b, 0x64, 0x19, 0xa9, 0x6d, 0xa4, 0x9e, 0x3e, 0x48, 0x17, 0x53, 0xe7, 0xe9, 0x6b, 0x71,
        0x6b, 0xdc, 0xcb, 0x6f,
    ];

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        let mut digest = Array4x12::default();
        let mut digest_512 = Array4x16::default();

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result = sha_acc_op.digest_384(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result =
                sha_acc_op.digest_512(data.len() as u32, 0, false, (&mut digest_512).into());
            assert!(result.is_ok());
            assert_eq!(digest_512, Array4x16::from(expected_512));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest1() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0x09, 0x33, 0x0C, 0x33, 0xF7, 0x11, 0x47, 0xE8, 0x3D, 0x19, 0x2F, 0xC7, 0x82, 0xCD, 0x1B,
        0x47, 0x53, 0x11, 0x1B, 0x17, 0x3B, 0x3B, 0x05, 0xD2, 0x2F, 0xA0, 0x80, 0x86, 0xE3, 0xB0,
        0xF7, 0x12, 0xFC, 0xC7, 0xC7, 0x1A, 0x55, 0x7E, 0x2D, 0xB9, 0x66, 0xC3, 0xE9, 0xFA, 0x91,
        0x74, 0x60, 0x39,
    ];
    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14,
        0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88,
        0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4,
        0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b,
        0x87, 0x4b, 0xe9, 0x09,
    ];

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        let mut digest = Array4x12::default();
        let mut digest_512 = Array4x16::default();

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result = sha_acc_op.digest_384(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result =
                sha_acc_op.digest_512(data.len() as u32, 0, false, (&mut digest_512).into());
            assert!(result.is_ok());
            assert_eq!(digest_512, Array4x16::from(expected_512));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest2() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0x67, 0x4b, 0x2e, 0x80, 0xff, 0x8d, 0x94, 0x00, 0x8d, 0xe7, 0x40, 0x9c, 0x7b, 0x1f, 0x87,
        0x8f, 0x9f, 0xae, 0x3a, 0x0a, 0x6d, 0xae, 0x2f, 0x98, 0x2c, 0xca, 0x7e, 0x3a, 0xae, 0xf9,
        0x1b, 0xf3, 0x25, 0xd3, 0xeb, 0x56, 0x82, 0x63, 0xa2, 0xe1, 0xe6, 0x85, 0x6a, 0xc7, 0x50,
        0x70, 0x06, 0x2a,
    ];
    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0x21, 0x7d, 0x3d, 0x9c, 0x09, 0x52, 0xc3, 0xe4, 0x90, 0x7f, 0x06, 0xd4, 0xfb, 0xf3, 0x44,
        0x60, 0xee, 0x85, 0x2c, 0x6a, 0xf5, 0x91, 0xb0, 0x7c, 0x2f, 0xa1, 0xc5, 0xe1, 0x64, 0x55,
        0x83, 0x63, 0x74, 0xc9, 0x5a, 0xe3, 0x3e, 0x18, 0x42, 0x27, 0x91, 0x3f, 0x8a, 0x2e, 0x22,
        0x7e, 0x3b, 0xbd, 0x51, 0x87, 0xce, 0x57, 0xaa, 0x1b, 0xad, 0x11, 0xa8, 0x0f, 0x62, 0x24,
        0x12, 0xeb, 0x08, 0x84,
    ];

    let mut digest = Array4x12::default();
    let mut digest_512 = Array4x16::default();

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result = sha_acc_op.digest_384(data.len() as u32, 0, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result =
                sha_acc_op.digest_512(data.len() as u32, 0, false, (&mut digest_512).into());
            assert!(result.is_ok());
            assert_eq!(digest_512, Array4x16::from(expected_512));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest_offset() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    let data = "abcdefghijklmnopqrst".as_bytes();
    let expected: [u8; SHA384_HASH_SIZE] = [
        0xd4, 0xcc, 0x9a, 0x0d, 0xc5, 0x46, 0x09, 0x40, 0xb0, 0x50, 0xa2, 0x42, 0x14, 0xf6, 0x78,
        0xf6, 0x3b, 0x99, 0x3e, 0xc3, 0xc5, 0x7d, 0xb9, 0xcc, 0x20, 0x7b, 0x20, 0x9c, 0xbd, 0xa7,
        0xcc, 0x09, 0xe9, 0x4a, 0x84, 0x62, 0x83, 0x56, 0x7d, 0x28, 0xd8, 0xc7, 0x73, 0xc1, 0x87,
        0x39, 0x07, 0xa7,
    ];
    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0xfb, 0x98, 0x27, 0x30, 0xed, 0x3d, 0x46, 0x8a, 0xe7, 0xbe, 0x25, 0x12, 0x1e, 0x45, 0xcf,
        0x4f, 0x7f, 0x2b, 0xd1, 0xfd, 0xd1, 0x77, 0x14, 0xf0, 0xae, 0x5b, 0x1c, 0xa9, 0x2d, 0x1f,
        0xf3, 0xf2, 0x35, 0x2d, 0x57, 0xc0, 0x8f, 0x88, 0xe9, 0x23, 0xf0, 0x88, 0x06, 0xc6, 0x01,
        0x6c, 0xc6, 0x7b, 0xf5, 0xf0, 0x09, 0x28, 0x27, 0x39, 0xa4, 0xe0, 0x0a, 0xf3, 0xce, 0x8c,
        0xa8, 0xf7, 0x04, 0xca,
    ];

    let mut digest = Array4x12::default();
    let mut digest_512 = Array4x16::default();

    if let Some(mut txn) = mbox.try_start_send_txn() {
        const CMD: u32 = 0x1c;
        assert!(txn.send_request(CMD, &data).is_ok());

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result = sha_acc_op.digest_384(8, 4, false, (&mut digest).into());
            assert!(result.is_ok());
            assert_eq!(digest, Array4x12::from(expected));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }

        if let Some(mut sha_acc_op) = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)
            .unwrap()
        {
            let result = sha_acc_op.digest_512(8, 4, false, (&mut digest_512).into());
            assert!(result.is_ok());
            assert_eq!(digest_512, Array4x16::from(expected_512));

            drop(sha_acc_op);
        } else {
            assert!(false);
        }
        drop(txn);
    };
}

fn test_digest_zero_size_buffer() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };

    let expected: [u8; SHA384_HASH_SIZE] = [
        0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3,
        0x6A, 0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6,
        0xE1, 0xDA, 0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48,
        0x98, 0xB9, 0x5B,
    ];
    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];

    let mut digest = Array4x12::default();
    let mut digest_512 = Array4x16::default();

    if let Some(mut sha_acc_op) = sha_acc
        .try_start_operation(ShaAccLockState::NotAcquired)
        .unwrap()
    {
        let result = sha_acc_op.digest_384(0, 0, true, (&mut digest).into());
        assert!(result.is_ok());
        assert_eq!(digest, Array4x12::from(expected));

        drop(sha_acc_op);
    } else {
        assert!(false);
    };

    if let Some(mut sha_acc_op) = sha_acc
        .try_start_operation(ShaAccLockState::NotAcquired)
        .unwrap()
    {
        let result = sha_acc_op.digest_512(0, 0, true, (&mut digest_512).into());
        assert!(result.is_ok());
        assert_eq!(digest_512, Array4x16::from(expected_512));

        drop(sha_acc_op);
    } else {
        assert!(false);
    };
}

fn test_digest_max_mailbox_size() {
    let mut sha_acc = unsafe { Sha2_512_384Acc::new(Sha512AccCsr::new()) };

    let expected: [u8; SHA384_HASH_SIZE] = [
        0xca, 0xd1, 0x95, 0xe7, 0xc3, 0xf2, 0xb2, 0x50, 0xb3, 0x5a, 0xc7, 0x8b, 0x17, 0xb7, 0xc2,
        0xf2, 0x29, 0xe1, 0x34, 0xb8, 0x61, 0xf2, 0xd0, 0xbe, 0x15, 0xb7, 0xd9, 0x54, 0x69, 0x71,
        0xf8, 0x5e, 0xc0, 0x40, 0x69, 0x3e, 0x5a, 0x22, 0x21, 0x88, 0x79, 0x77, 0xfd, 0xea, 0x6f,
        0x89, 0xef, 0xee,
    ];
    let expected_512: [u8; SHA512_HASH_SIZE] = [
        0x4e, 0xd8, 0x3e, 0x40, 0xc9, 0xcf, 0x32, 0xac, 0x2c, 0x59, 0x12, 0x5a, 0x01, 0x17, 0x0b,
        0xc9, 0x7f, 0x20, 0x55, 0x09, 0x52, 0xc8, 0xca, 0x20, 0xff, 0xe1, 0xb2, 0xa5, 0x9d, 0x1b,
        0x1e, 0xd9, 0xc8, 0x42, 0x6c, 0x51, 0x5f, 0x76, 0x29, 0xd1, 0xbb, 0x5e, 0x4c, 0xdc, 0x53,
        0xdd, 0x70, 0xff, 0xcf, 0x67, 0x20, 0x3d, 0x59, 0xe7, 0x0a, 0x55, 0x94, 0x92, 0xe5, 0xff,
        0x0e, 0x71, 0x22, 0x78,
    ];

    {
        // Clear the mailbox SRAM; FPGA model doesn't clear this on reset.
        let mut mbox = unsafe { MboxCsr::new() };
        // Grab lock
        assert!(!mbox.regs().lock().read().lock());
        let mbox_sram = unsafe {
            slice::from_raw_parts_mut(
                memory_layout::MBOX_ORG as *mut u8,
                memory_layout::MBOX_SIZE as usize,
            )
        };
        mbox_sram.fill(0);
        mbox.regs_mut().unlock().write(|w| w.unlock(true));
    }

    let mut digest = Array4x12::default();
    let mut digest_512 = Array4x16::default();

    if let Some(mut sha_acc_op) = sha_acc
        .try_start_operation(ShaAccLockState::NotAcquired)
        .unwrap()
    {
        let result = sha_acc_op.digest_384(
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

    if let Some(mut sha_acc_op) = sha_acc
        .try_start_operation(ShaAccLockState::NotAcquired)
        .unwrap()
    {
        let result = sha_acc_op.digest_512(
            MAX_MAILBOX_CAPACITY_BYTES as u32,
            0,
            true,
            (&mut digest_512).into(),
        );
        assert!(result.is_ok());
        assert_eq!(digest_512, Array4x16::from(expected_512));

        drop(sha_acc_op);
    } else {
        assert!(false);
    };
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

test_suite! {
    test_kat,
    test_digest_max_mailbox_size,
    test_digest_offset,
    test_digest0,
    test_digest1,
    test_digest2,
    test_digest_zero_size_buffer,
}
