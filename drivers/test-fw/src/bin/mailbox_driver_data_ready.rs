// Licensed under the Apache-2.0 license

//! Test firmware that sends a mailbox request and verifies that a DataReady
//! response is treated as an error by the driver.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, CaliptraError, Mailbox};
use caliptra_registers::mbox::MboxCsr;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };

    // Send a request; the SoC will respond with DataReady
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.send_request(0xd000_0000, b"Hello").unwrap();
    while !txn.is_response_ready() {}

    // complete() should return an error since DataReady is unexpected
    let result = txn.complete();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CaliptraError::DRIVER_MAILBOX_FSM_ERROR
    ));
    drop(txn);

    // Mailbox should be back to idle after the unlock; send another request
    // to prove recovery worked
    let mut txn = mbox.wait_until_start_send_txn();
    txn.send_request(0xd000_1000, b"").unwrap();
    while !txn.is_response_ready() {}
    txn.complete().unwrap();
}
