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

/// Test case to send data to the mailbox.
fn test_try_send_data() {
    let data = [0xdeadbeef_u32; 16];
    const CMD: u32 = 42;

    let data_to_send =
        unsafe { slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * size_of::<u32>()) };

    // Try start a send transaction
    let Some(mut txn) = Mailbox::default().try_start_send_txn() else { panic!("Failed to start send transaction"); };
    // Write the command , data buffer length and try to write the data buffer
    // to the mailbox using builder pattern.
    let txn = txn
        .write_cmd(CMD)
        .try_write_dlen((data_to_send.len()) as u32)
        .unwrap_or_else(|_| panic!("Failed to write command and data length to mailbox"));

    let mut txn = txn
        .try_write_data(data_to_send)
        .unwrap_or_else(|_| panic!("Failed to write data to mailbox"));

    let mut txn = txn.execute();

    let Some(rcv_txn) = Mailbox::default().try_start_recv_txn() else { panic!("Failed to start receive transaction"); };

    assert_eq!(rcv_txn.read_cmd(), CMD);
    assert_eq!(rcv_txn.read_dlen(), data_to_send.len() as u32);

    let buf: &mut [u8] = &mut [0; 64];
    let rcv_txn = rcv_txn
        .try_read_data(buf)
        .unwrap_or_else(|_| panic!("Failed to read data from mailbox"));

    assert_eq!(buf.len(), data_to_send.len());
    assert_eq!(buf, data_to_send);
}

test_suite! {
    test_try_send_data,
}
