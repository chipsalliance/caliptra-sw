// Licensed under the Apache-2.0 license

//! Send DICE certificates over the mailbox

#![no_main]
#![no_std]

use caliptra_common::mailbox_api::CommandId;
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_runtime::{dice, Drivers};
use caliptra_test_harness::{runtime_handlers, test_suite};
use zerocopy::AsBytes;

fn mbox_responder() {
    let mut fht = unsafe { caliptra_common::FirmwareHandoffTable::try_load().unwrap() };
    let drivers = unsafe { Drivers::new_from_registers(&mut fht).unwrap() };
    let mut mbox = drivers.mbox;

    loop {
        while !mbox.is_cmd_ready() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd();

        match cmd {
            // Send LDevID Cert
            CommandId(0x1000_0000) => {
                let mut ldev = [0u8; 1024];
                dice::copy_ldevid_cert(&drivers.data_vault, &mut ldev).unwrap();
                mbox.write_response(&ldev).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Send FMC Alias Cert
            CommandId(0x2000_0000) => {
                let mut fmc = [0u8; 1024];
                dice::copy_fmc_alias_cert(&drivers.data_vault, &mut fmc).unwrap();
                mbox.write_response(&fmc).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Send IDevID Public Key
            CommandId(0x3000_0000) => {
                mbox.write_response(drivers.fht.idev_dice_pub_key.as_bytes())
                    .unwrap();
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
