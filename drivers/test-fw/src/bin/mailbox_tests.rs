/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox_tests.rs

Abstract:

    File contains test cases for MAILBOX API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{Execute, Mailbox, MailboxSendTxn};
use caliptra_registers::mbox::{self};
use core::mem::size_of;
use core::slice;
use zerocopy::AsBytes;

use caliptra_test_harness::test_suite;

fn send_request(cmd: u32, data_to_send: &[u8]) -> MailboxSendTxn<Execute> {
    let data_to_send = &[0u8; 0];
    let txn = MailboxSendTxn::default()
        .write_cmd(cmd)
        .try_write_dlen((data_to_send.len()) as u32)
        .unwrap_or_else(|_| loop {});

    let mut txn = txn.try_write_data(data_to_send).unwrap_or_else(|_| loop {});

    let mut txn = txn.execute();

    txn
}

fn test_send_txn() {
    if let Some(txn) = Mailbox::default().try_start_send_txn() {
        let dummy: &[u8; 0] = &[0u8; 0];
        let mut txn = send_request(0x42, dummy);
        loop {
            if let Some(rcv_txn) = Mailbox::default().try_start_recv_txn() {
                if caliptra_drivers::Mailbox::default().cmd() != 0x42 {
                    assert!(false);
                } else {
                    rcv_txn.complete(false);
                    txn.complete();
                    break;
                }
            } else {
                assert!(false);
            }
        }
    } else {
        assert!(false);
    }
}

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

test_suite! {
    test_send_txn_drop,
    test_send_txn,
}
