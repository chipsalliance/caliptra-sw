// Licensed under the Apache-2.0 license

//! Send DICE certificates over the mailbox

#![no_main]
#![no_std]

use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_runtime::{dice, Drivers};
use caliptra_test_harness::{runtime_handlers, test_suite};

fn mbox_responder() {
    let drivers = unsafe { Drivers::new_from_registers() };
    let mut mbox = drivers.mbox;

    loop {
        while !mbox.is_cmd_ready() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd();

        match cmd {
            // Send LDevID Cert
            0x1000_0000 => {
                let mut ldev = [0u8; 1024];
                dice::copy_ldevid_cert(&drivers.data_vault, &mut ldev).unwrap();
                mbox.write_response(&ldev).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Send FMC Alias Cert
            0x2000_0000 => {
                let mut fmc = [0u8; 1024];
                dice::copy_fmc_alias_cert(&drivers.data_vault, &mut fmc).unwrap();
                mbox.write_response(&fmc).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            _ => {
                mbox.set_status(MboxStatusE::CmdFailure);
            }
        }
    }
}

test_suite! {
    mbox_responder,
}
