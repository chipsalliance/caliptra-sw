// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

use caliptra_registers;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let soc_ifc = caliptra_registers::soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_flow_status().write(|w| w.ready_for_fw(true));
    let mbox = caliptra_registers::mbox::RegisterBlock::mbox_csr();

    loop {
        while !mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd().read();

        match cmd {
            // Consumes input, and echoes the request back as the response with
            // the command-id prepended.
            0x1000_0000 => {
                let dlen = mbox.dlen().read();
                let dlen_words = usize::try_from((dlen + 3) / 4).unwrap();
                let mut buf = [0u32; 8];
                for i in 0..dlen_words {
                    buf[i] = mbox.dataout().read();
                }
                mbox.dlen().write(|_| dlen + 4);
                mbox.datain().write(|_| cmd);
                for i in 0..dlen_words {
                    mbox.datain().write(|_| buf[i]);
                }
                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            // Returns a response of 7 hard-coded bytes; doesn't consume input.
            0x1000_1000 => {
                mbox.dlen().write(|_| 7);
                mbox.datain().write(|_| 0x6745_2301);
                mbox.datain().write(|_| 0xefcd_ab89);

                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            // Returns a response of 0 bytes; doesn't consume input.
            0x1000_2000 => {
                mbox.dlen().write(|_| 0);
                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            // Returns a success response; doesn't consume input.
            0x2000_0000 => {
                mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            }
            // Everything else returns a failure response; doesn't consume input.
            _ => {
                mbox.status().write(|w| w.status(|w| w.cmd_failure()));
            }
        }
    }
}
