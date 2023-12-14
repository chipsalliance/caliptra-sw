// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use core::mem::size_of;

use caliptra_common::mailbox_api::CommandId;
use caliptra_drivers::{
    pcr_log::{PCR_ID_STASH_MEASUREMENT, RT_FW_JOURNEY_PCR},
    Array4x12,
};
use caliptra_registers::{mbox::enums::MboxStatusE, soc_ifc::SocIfcReg};
use caliptra_runtime::{ContextState, DpeInstance, Drivers, U8Bool, MAX_HANDLES};
use caliptra_test_harness::{runtime_handlers, test_suite};
use zerocopy::{AsBytes, FromBytes};

const FW_LOAD_CMD_OPCODE: u32 = CommandId::FIRMWARE_LOAD.0;

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
                let out: [u8; 48] = digest.into();
                mbox.write_response(&out).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Read PCR_ID_STASH_MEASUREMENT
            CommandId(0x5000_0000) => {
                let pcr_id_stash_measurement: [u8; 48] =
                    drivers.pcr_bank.read_pcr(PCR_ID_STASH_MEASUREMENT).into();
                mbox.write_response(&pcr_id_stash_measurement).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Read DPE root context measurement
            CommandId(0x6000_0000) => {
                let root_idx =
                    Drivers::get_dpe_root_context_idx(&drivers.persistent_data.get().dpe).unwrap();
                let root_measurement = drivers.persistent_data.get().dpe.contexts[root_idx]
                    .tci
                    .tci_current
                    .as_bytes();
                mbox.write_response(root_measurement).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Read tags
            CommandId(0x7000_0000) => {
                let context_tags = drivers.persistent_data.get().context_tags;
                let context_has_tag = drivers.persistent_data.get().context_has_tag;
                const CONTEXT_TAGS_SIZE: usize = MAX_HANDLES * size_of::<u32>();
                const CONTEXT_HAS_TAG_SIZE: usize = MAX_HANDLES * size_of::<U8Bool>();
                let mut tags_info = [0u8; CONTEXT_TAGS_SIZE + CONTEXT_HAS_TAG_SIZE];
                tags_info[..CONTEXT_TAGS_SIZE].copy_from_slice(context_tags.as_bytes());
                tags_info[CONTEXT_TAGS_SIZE..].copy_from_slice(context_has_tag.as_bytes());
                mbox.write_response(tags_info.as_bytes()).unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Corrupt context_tags
            CommandId(0x8000_0000) => {
                let size = mbox.dlen() as usize;
                let input_bytes = &mbox.raw_mailbox_contents()[..size];

                let corrupted_context_tags = <[u32; MAX_HANDLES]>::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().context_tags = corrupted_context_tags;
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Corrupt context_has_tag
            CommandId(0x9000_0000) => {
                let size = mbox.dlen() as usize;
                let input_bytes = &mbox.raw_mailbox_contents()[..size];

                let corrupted_context_has_tag =
                    <[U8Bool; MAX_HANDLES]>::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().context_has_tag = corrupted_context_has_tag;
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Read DpeInstance
            CommandId(0xA000_0000) => {
                mbox.write_response(drivers.persistent_data.get().dpe.as_bytes())
                    .unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Corrupt DpeInstance
            CommandId(0xB000_0000) => {
                let size = mbox.dlen() as usize;
                let input_bytes = &mbox.raw_mailbox_contents()[..size];

                let corrupted_dpe = DpeInstance::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().dpe = corrupted_dpe;
                mbox.set_status(MboxStatusE::DataReady);
            }
            // Read PcrResetCounter
            CommandId(0xC000_0000) => {
                mbox.write_response(drivers.persistent_data.get().pcr_reset.as_bytes())
                    .unwrap();
                mbox.set_status(MboxStatusE::DataReady);
            }
            CommandId(FW_LOAD_CMD_OPCODE) => {
                unsafe { SocIfcReg::new() }
                    .regs_mut()
                    .internal_fw_update_reset()
                    .write(|w| w.core_rst(true));
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
