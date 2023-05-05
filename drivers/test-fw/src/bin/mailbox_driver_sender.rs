// Licensed under the Apache-2.0 license

//! A very simple program that uses the driver to send mailbox messages

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, Mailbox, MailboxSendTxn};

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn start_send_txn() -> MailboxSendTxn {
    let mbox = Mailbox::default();
    loop {
        if let Some(txn) = mbox.try_start_send_txn() {
            return txn;
        }
    }
}

#[no_mangle]
extern "C" fn main() {
    // 0 byte request
    let mut txn = start_send_txn();
    txn.send_request(0xa000_0000, b"").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();

    // 3 byte request
    let mut txn = start_send_txn();
    txn.send_request(0xa000_1000, b"Hi!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();

    // 4 byte request
    let mut txn = start_send_txn();
    txn.send_request(0xa000_2000, b"Hi!!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();

    // 6 byte request
    let mut txn = start_send_txn();
    txn.send_request(0xa000_3000, b"Hello!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();

    // 8 byte request
    let mut txn = start_send_txn();
    txn.send_request(0xa000_4000, b"Hello!!!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();

    // write_cmd / write_dlen / execute_request used separately
    let mut txn = start_send_txn();
    txn.write_cmd(0xb000_0000).unwrap();
    txn.write_dlen(0).unwrap();
    txn.execute_request().unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
}
