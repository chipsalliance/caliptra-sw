/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox_tests.rs

Abstract:

    File contains test cases for MAILBOX API

--*/

#![no_std]
#![no_main]

use caliptra_lib::Mailbox;
mod harness;

fn test_mailbox_loopback() {
    // Initialize a send buffer of 4 dwords
    let data_send: [u32; 4] = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];

    // Initialize an empty receive buffer of 4 dwords
    let mut data_recv: [u32; 4] = [0; 4];

    // Send Data to the Mailbox
    let mut result = Mailbox::send(0xdeadbeef, &data_send);
    assert!(result.is_ok());

    // Retrieve Data Len (in Bytes) and check against the Data Buffer
    let dlen = Mailbox::get_data_len();
    assert_eq!(dlen, (data_send.len() as u32) * 4);

    // Receive Data Back from the Mailbox
    result = Mailbox::recv(&mut data_recv, |_x, _y| true);
    assert!(result.is_ok());

    // Verify Received Data against what it was sent
    assert_eq!(data_send, data_recv);
}

test_suite! {
    test_mailbox_loopback,
}
