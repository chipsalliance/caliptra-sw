// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use caliptra_common::mailbox_api::CommandId;
use caliptra_drivers::{pcr_log::RT_FW_JOURNEY_PCR, Array4x12};
use caliptra_registers::mbox::enums::MboxStatusE;
use caliptra_runtime::{ContextState, Drivers};
use caliptra_test_harness::{runtime_handlers, test_suite};
use zerocopy::AsBytes;

fn mbox_responder() {
    let mut drivers = unsafe { Drivers::new_from_registers().unwrap() };
    assert!(drivers.persistent_data.get().fht.is_valid());
    let mut mbox = drivers.mbox;

    loop {
        while !mbox.is_cmd_ready() {
            // Wait for a request from the SoC.
        }
        let cmd = mbox.cmd();

        match cmd {
            // Read RT_FW_JOURNEY_PCR
            CommandId(0x1000_0000) => {
                let rt_journey_pcr: [u8; 48] = drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR).into();
                mbox.write_response(&rt_journey_pcr).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Reconstruct valid mbox pauser hash
            CommandId(0x2000_0000) => {
                const PAUSER_COUNT: usize = 5;
                let mbox_valid_pauser: [u32; PAUSER_COUNT] = drivers.soc_ifc.mbox_valid_pauser();
                let mbox_pauser_lock: [bool; PAUSER_COUNT] = drivers.soc_ifc.mbox_pauser_lock();
                let mut digest_op = drivers.sha384.digest_init().unwrap();
                for i in 0..PAUSER_COUNT {
                    if mbox_pauser_lock[i] {
                        digest_op.update(mbox_valid_pauser[i].as_bytes()).unwrap();
                    }
                }

                let mut valid_pauser_hash = Array4x12::default();
                digest_op.finalize(&mut valid_pauser_hash).unwrap();
                mbox.write_response(valid_pauser_hash.as_bytes()).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Hash DPE TCI data
            CommandId(0x3000_0000) => {
                let mut hasher = drivers.sha384.digest_init().unwrap();
                for context in drivers.persistent_data.get().dpe.contexts {
                    if context.state != ContextState::Inactive {
                        hasher.update(context.tci.tci_current.as_bytes()).unwrap();
                    }
                }
                let mut digest = Array4x12::default();
                hasher.finalize(&mut digest).unwrap();
                mbox.write_response(digest.as_bytes()).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Hash input data
            CommandId(0x4000_0000) => {
                let size = mbox.dlen() as usize;
                let input_bytes = &mbox.raw_mailbox_contents()[..size];
                mbox.write_response(drivers.sha384.digest(input_bytes).unwrap().as_bytes())
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
