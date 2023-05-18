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
    let mut mbox = Mailbox::default();
    loop {
        if let Some(txn) = mbox.try_start_send_txn() {
            return txn;
        }
    }
}

#[no_mangle]
extern "C" fn main() {
    // 0 byte request
    // The SoC will try to corrupt the CMD opcode and the Dlen field.
    let mut txn = start_send_txn();
    txn.send_request(0xa000_0000, b"").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
}
