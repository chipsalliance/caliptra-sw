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

test_suite! {
    test_send_txn_drop,
}
