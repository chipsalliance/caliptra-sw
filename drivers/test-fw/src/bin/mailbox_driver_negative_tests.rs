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
    // 0 byte request
    // The SoC will try to corrupt the CMD opcode and the Dlen field.
    loop {
        let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
        let mut txn = mbox.try_start_send_txn().unwrap();
        txn.send_request(0xa000_0000, b"").unwrap();
        while !txn.is_response_ready() {}
        // complete() detects FSM error state, writes unlock to recover,
        // and returns Err(DRIVER_MAILBOX_FSM_ERROR). Ignore the error
        // and loop to retry the transaction.
        let _ = txn.complete();
    }
}
