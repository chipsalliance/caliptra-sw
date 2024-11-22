// Licensed under the Apache-2.0 license

//! A very simple program that uses the driver to send mailbox messages

#![no_main]
#![no_std]

use caliptra_registers::mbox::MboxCsr;
// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, Mailbox};

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

fn mbox_fsm_error() -> bool {
    let mbox = unsafe { MboxCsr::new() };
    mbox.regs().status().read().mbox_fsm_ps().mbox_error()
}

#[no_mangle]
extern "C" fn main() {
    // 0 byte request
    // The SoC will try to corrupt the CMD opcode and the Dlen field.
    loop {
        let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
        let mut txn = mbox.try_start_send_txn().unwrap();
        txn.send_request(0xa000_0000, b"").unwrap();
        // TODO: get rid of mbox_fsm_error() and make the driver handle this correctly (see #718)
        while !txn.is_response_ready() && !mbox_fsm_error() {}
        txn.complete().unwrap();
        drop(txn);

        // Clear any error states
        // TODO: This should probably be done in the driver
        let mut reg = unsafe { MboxCsr::new() };
        reg.regs_mut().unlock().write(|w| w.unlock(true));
    }
}
