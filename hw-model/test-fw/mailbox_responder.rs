// Licensed under the Apache-2.0 license

//! A very simple program that responds to the mailbox.

#![no_main]
#![no_std]

// Needed to bring in startup code
#[allow(unused)]
use caliptra_test_harness;

use caliptra_drivers::cprint;
use caliptra_registers::{self, mbox::MboxCsr, sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg};
use caliptra_test_harness_types::mailbox_responder::{
    ECHO_MAX_LEN, FIXED_RESPONSE_LEN, FIXED_RESPONSE_WORDS, MBOX_CMD_ECHO, MBOX_CMD_EMPTY_RESPONSE,
    MBOX_CMD_FIXED_RESPONSE, MBOX_CMD_GET_RESPONSE, MBOX_CMD_NODATA, MBOX_CMD_SET_RESPONSE,
    MBOX_CMD_UNLOCK_SHA512_ACC,
};

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
extern "C" fn main() {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    let mut mbox = unsafe { MboxCsr::new() };
    let mbox = mbox.regs_mut();

    let mut sha512acc = unsafe { Sha512AccCsr::new() };
    let sha512acc = sha512acc.regs_mut();

    soc_ifc
        .regs_mut()
        .cptra_flow_status()
        .write(|w| w.ready_for_mb_processing(true));

    let mut replay_buf_len = 0;
    let mut replay_buf = [0u32; 2048];
    loop {
        while !mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd().read();

        match cmd {
            // Consumes input, and echoes the request back as the response with
            // the command-id prepended.
            MBOX_CMD_ECHO => {
                let dlen = mbox.dlen().read();
                let dlen_words = usize::try_from((dlen + 3) / 4).unwrap();
                let mut buf = [0u32; ECHO_MAX_LEN / 4];
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
            MBOX_CMD_FIXED_RESPONSE => {
                mbox.dlen().write(|_| FIXED_RESPONSE_LEN);
                for word in FIXED_RESPONSE_WORDS {
                    mbox.datain().write(|_| word);
                }

                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            // Returns a response of 0 bytes; doesn't consume input.
            MBOX_CMD_EMPTY_RESPONSE => {
                mbox.dlen().write(|_| 0);
                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            // Returns a success response; doesn't consume input.
            MBOX_CMD_NODATA => {
                mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            }
            // Store a buf to be returned by MBOX_CMD_GET_RESPONSE
            MBOX_CMD_SET_RESPONSE => {
                let dlen = mbox.dlen().read();
                let dlen_words = usize::try_from((dlen + 3) / 4).unwrap();
                for i in 0..usize::min(dlen_words, replay_buf.len()) {
                    replay_buf[i] = mbox.dataout().read();
                }
                replay_buf_len = u32::min(dlen, u32::try_from(replay_buf.len()).unwrap());
                mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            }
            MBOX_CMD_GET_RESPONSE => {
                cprint!("|");
                let dlen = mbox.dlen().read();
                let dlen_words = usize::try_from((dlen + 3) / 4).unwrap();
                for i in 0..(dlen_words) {
                    if i == dlen_words - 1 && dlen % 4 != 0 {
                        let word_bytes = mbox.dataout().read().to_le_bytes();
                        for byte in &word_bytes[..dlen as usize % 4] {
                            cprint!("{:02x}", *byte);
                        }
                    } else {
                        cprint!("{:08x}", mbox.dataout().read().to_be());
                    }
                }
                cprint!("|");
                mbox.dlen().write(|_| replay_buf_len);
                let dlen_words = usize::try_from((replay_buf_len + 3) / 4).unwrap();
                for i in 0..dlen_words {
                    mbox.datain().write(|_| replay_buf[i]);
                }
                mbox.status().write(|w| w.status(|w| w.data_ready()));
            }
            MBOX_CMD_UNLOCK_SHA512_ACC => {
                // Unlock sha512acc peripheral by writing 1
                sha512acc.lock().write(|w| w.lock(true));
                mbox.status().write(|w| w.status(|w| w.cmd_complete()));
            }
            // Everything else returns a failure response; doesn't consume input.
            _ => {
                mbox.status().write(|w| w.status(|w| w.cmd_failure()));
            }
        }
    }
}
