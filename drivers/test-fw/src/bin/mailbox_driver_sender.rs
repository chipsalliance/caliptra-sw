// Licensed under the Apache-2.0 license

//! A very simple program that uses the driver to send mailbox messages

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, Mailbox};
use caliptra_registers::mbox::MboxCsr;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    // 0 byte request
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.send_request(0xa000_0000, b"").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);

    // 3 byte request
    let mut txn = mbox.wait_until_start_send_txn();
    txn.send_request(0xa000_1000, b"Hi!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);

    // 4 byte request
    let mut txn = mbox.wait_until_start_send_txn();
    txn.send_request(0xa000_2000, b"Hi!!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);

    // 6 byte request
    let mut txn = mbox.wait_until_start_send_txn();
    txn.send_request(0xa000_3000, b"Hello!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);

    // 8 byte request
    let mut txn = mbox.wait_until_start_send_txn();
    txn.send_request(0xa000_4000, b"Hello!!!").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);

    // write_cmd / write_dlen / execute_request used separately
    let mut txn = mbox.wait_until_start_send_txn();
    txn.write_cmd(0xb000_0000).unwrap();
    txn.write_dlen(0).unwrap();
    txn.execute_request().unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
    drop(txn);
}
