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
    let mbox = unsafe { MboxCsr::new() };
    println!(
        "locked state is  {} mailbox present state is {} is in error {}",
        mbox.regs().lock().read().lock(),
        mbox.regs().status().read().mbox_fsm_ps() as u32,
        mbox.regs().status().read().mbox_fsm_ps().mbox_error() as u32
    );
    loop {}
}

fn mbox_fsm_error() -> bool {
    let mbox = unsafe { MboxCsr::new() };
    mbox.regs().status().read().mbox_fsm_ps().mbox_error()
}

#[no_mangle]
extern "C" fn main() {
    let mut mbox = Mailbox::new(unsafe { MboxCsr::new() });

    // Transition from execute to idle
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.write_cmd(0).unwrap();
    txn.write_dlen(1).unwrap();
    txn.execute_request().unwrap();
    drop(txn);
    assert_eq!(mbox_fsm_error(), false);

    // Transition from rdy_for_data to idle
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.write_cmd(0).unwrap();
    txn.write_dlen(1).unwrap();
    drop(txn);
    assert_eq!(mbox_fsm_error(), false);

    // Transition from rdy_for_dlen to idle
    let mut txn = mbox.try_start_send_txn().unwrap();
    txn.write_cmd(0).unwrap();
    drop(txn);
    assert_eq!(mbox_fsm_error(), false);

    // Transition from rdy_for_cmd to idle
    let txn = mbox.try_start_send_txn().unwrap();
    drop(txn);
    assert_eq!(mbox_fsm_error(), false);
    let _ = mbox.try_start_send_txn().unwrap();
}
