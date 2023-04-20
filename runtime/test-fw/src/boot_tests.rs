/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_drivers::Mailbox;
use caliptra_test_harness::{runtime_handlers, test_suite};
use core::mem;

const MBOX_DOWNLOAD_FIRMWARE_CMD_ID: u32 = 0x46574C44;

fn test_boot() {
    // Complete the pending download-firmware mailbox transaction started in the
    // ROM.
    let mbox = Mailbox::default();
    if let Some(txn) = mbox.try_start_recv_txn() {
        let mut txn = mem::ManuallyDrop::new(txn);
        if txn.cmd() == MBOX_DOWNLOAD_FIRMWARE_CMD_ID {
            txn.complete(true).unwrap();
        }
    }
    assert!(true);
}

test_suite! {
    test_boot,
}
