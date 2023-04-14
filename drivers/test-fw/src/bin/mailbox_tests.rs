/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox_tests.rs

Abstract:

    File contains test cases for MAILBOX API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::Mailbox;
use caliptra_registers::mbox::{self};
use core::mem::size_of;
use core::slice;
use zerocopy::AsBytes;

use caliptra_test_harness::test_suite;

fn test_send_txn_drop() {
    let mut ii = 0;
    while ii < 2 {
        if let Some(txn) = Mailbox::default().try_start_send_txn() {
            drop(txn);
        } else {
            assert!(false);
        }
        ii = ii + 1;
    }
}

fn test_send_txn_error() {
    if let Some(mut txn) = Mailbox::default().try_start_send_txn() {
        assert!(txn.write_dlen(0x01).is_err());
        assert!(txn.execute_request().is_err());
        assert!(txn.complete().is_err());
        drop(txn);
    }
}

fn test_try_start_rcv_txn_error() {
    if let Some(_recv_txn) = Mailbox::default().try_start_recv_txn() {
        assert!(false);
    }
    if let Some(_txn) = Mailbox::default().try_start_send_txn() {
        if let Some(_recv_txn) = Mailbox::default().try_start_recv_txn() {
            assert!(false);
        }
    } else {
        assert!(false);
    }
}

fn test_mailbox_loopback() {
    // Send an u32 to ourselves.
    #[repr(align(4))]
    struct Aligner {
        pub data_to_send: [u32; 4],
    }

    impl Aligner {
        pub fn new() -> Self {
            Self {
                data_to_send: [
                    0xAABBCCDD_u32,
                    0x11223344_u32,
                    0x55667788_u32,
                    0x99AABBCC_u32,
                ],
            }
        }
    }
    let aligner = Aligner::new();
    let request = unsafe {
        slice::from_raw_parts(
            aligner.data_to_send.as_ptr() as *const u8,
            4 * size_of::<u32>() - 1,
        )
    };
    let mut request_received = [0u32; 32];

    let mut ii = 0;
    while ii < 2 {
        if let Some(mut txn) = Mailbox::default().try_start_send_txn() {
            const CMD: u32 = 0x1c;

            assert!(txn.send_request(CMD, request).is_ok());
            drop(txn);

            let mbox = mbox::RegisterBlock::mbox_csr();
            assert_eq!(mbox.dlen().read(), request.len() as u32);
            // Initialize an empty receive buffer.
            // Send a bigger buffer than needed.
            if let Some(mut recv_txn) = Mailbox::default().try_start_recv_txn() {
                assert_eq!(mbox.dlen().read(), recv_txn.dlen());
                assert!(recv_txn.recv_request(&mut request_received[..]).is_ok());
                assert_eq!(request, &request_received.as_bytes()[..request.len()]);
                assert!(recv_txn.recv_request(&mut request_received[..]).is_err());
                for nn in &mut request_received[0..request.len()] {
                    *nn = 42
                }
            }
        } else {
            assert!(false);
        }
        ii = ii + 1;
    }
}

test_suite! {
    test_try_start_rcv_txn_error,
    test_send_txn_drop,
    test_send_txn_error,
    test_mailbox_loopback,
}
