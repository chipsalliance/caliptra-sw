// Licensed under the Apache-2.0 license

//! A very simple program that uses the driver to send mailbox messages

#![no_main]
#![no_std]

use caliptra_registers::mbox::MboxCsr;
// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness::{self, println};

use caliptra_drivers::{self, cprintln, Mailbox};

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
    let mut mbox = unsafe { Mailbox::new(MboxCsr::new()) };
    let mut txn = mbox.try_start_send_txn().unwrap();

    let s6 = 0x3004_0000u32;

    for i in 0..128 {
        unsafe { core::ptr::write_volatile((s6 as *mut u32).add(i), i as u32) };
    }

    let mut buffer = [0u32; 128];
    let sp = &mut buffer as *mut u32;
    let mut s3: u32;
    // s6 and sp are input arguments (as pointers)
    unsafe {
        core::arch::asm!(
            "lw a0, 16({s6})",
            "lw a1, 12({s6})",
            "lw s3, 4({s6})", // fails
            "lw s8, 8({s6})",
            "sw a1, 16({sp})",

            // inputs
            s6 = in(reg) s6,
            sp = in(reg) sp,
            // output and clobbers
            out("a0") _,
            out("a1") _,
            out("s3") s3,
            out("s8") _,
        );
    }

    cprintln!("s3 = {}", s3);

    // txn.send_request(0xa000_0000, b"").unwrap();
    // // TODO: get rid of mbox_fsm_error() and make the driver handle this correctly (see #718)
    // while !txn.is_response_ready() && !mbox_fsm_error() {}
    // txn.complete().unwrap();
    // drop(txn);
    // drop(mbox);

    // // Clear any error states
    // // TODO: This should probably be done in the driver
    // let mut reg = unsafe { MboxCsr::new() };
    // reg.regs_mut().unlock().write(|w| w.unlock(true));
}
