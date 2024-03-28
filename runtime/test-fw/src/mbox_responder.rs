// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use core::mem::size_of;

use caliptra_common::{handle_fatal_error, mailbox_api::CommandId};
use caliptra_drivers::{
    cprintln,
    pcr_log::{PCR_ID_STASH_MEASUREMENT, RT_FW_JOURNEY_PCR},
    Array4x12, CaliptraError, CaliptraResult,
};
use caliptra_registers::{mbox::enums::MboxStatusE, soc_ifc::SocIfcReg};
use caliptra_runtime::{
    mailbox::Mailbox, ContextState, DpeInstance, Drivers, RtBootStatus, TciMeasurement, U8Bool,
    MAX_HANDLES,
};
use caliptra_test_harness::{runtime_handlers, test_suite};
use zerocopy::{AsBytes, FromBytes};

const OPCODE_READ_RT_FW_JOURNEY: u32 = 0x1000_0000;
const OPCODE_READ_MBOX_PAUSER_HASH: u32 = 0x2000_0000;
const OPCODE_HASH_DPE_TCI_DATA: u32 = 0x3000_0000;
const OPCODE_READ_STASHED_MEASUREMENT_PCR: u32 = 0x5000_0000;
const OPCODE_READ_DPE_ROOT_CONTEXT_MEASUREMENT: u32 = 0x6000_0000;
const OPCODE_READ_DPE_TAGS: u32 = 0x7000_0000;
const OPCODE_CORRUPT_CONTEXT_TAGS: u32 = 0x8000_0000;
const OPCODE_CORRUPT_CONTEXT_HAS_TAG: u32 = 0x9000_0000;
const OPCODE_READ_DPE_INSTANCE: u32 = 0xA000_0000;
const OPCODE_CORRUPT_DPE_INSTANCE: u32 = 0xB000_0000;
const OPCODE_READ_PCR_RESET_COUNTER: u32 = 0xC000_0000;
const OPCODE_CORRUPT_DPE_ROOT_TCI: u32 = 0xD000_0000;
const OPCODE_FW_LOAD: u32 = CommandId::FIRMWARE_LOAD.0;

fn read_request(mbox: &Mailbox) -> &[u8] {
    let size = mbox.dlen() as usize;
    &mbox.raw_mailbox_contents()[..size]
}

fn write_response(mbox: &mut Mailbox, data: &[u8]) {
    mbox.write_response(data).unwrap();
    mbox.set_status(MboxStatusE::DataReady);
}

const BANNER: &str = r#"
  ____      _ _       _               ____ _____
 / ___|__ _| (_)_ __ | |_ _ __ __ _  |  _ \_   _|
| |   / _` | | | '_ \| __| '__/ _` | | |_) || |
| |__| (_| | | | |_) | |_| | | (_| | |  _ < | |
 \____\__,_|_|_| .__/ \__|_|  \__,_| |_| \_\|_|
               |_|
"#;

#[no_mangle]
#[allow(clippy::empty_loop)]
fn rt_entry() -> () {
    cprintln!("{}", BANNER);
    let mut drivers = unsafe {
        Drivers::new_from_registers().unwrap_or_else(|e| {
            cprintln!("[rt] Runtime can't load drivers");
            handle_fatal_error(e.into());
        })
    };
    drivers.run_reset_flow().unwrap_or_else(|e| {
        cprintln!("[rt] Runtime failed reset flow");
        handle_fatal_error(e.into());
    });

    if !drivers.persistent_data.get().fht.is_valid() {
        cprintln!("Runtime can't load FHT");
        handle_fatal_error(CaliptraError::RUNTIME_HANDOFF_FHT_NOT_LOADED.into());
    }
    cprintln!("[rt] Runtime listening for mailbox commands...");
    if let Err(e) = handle_mailbox_commands(&mut drivers) {
        handle_fatal_error(e.into());
    }
    return;
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) -> CaliptraResult<()> {
    // Indicator to SOC that RT firmware is ready
    drivers.soc_ifc.assert_ready_for_runtime();
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());
    loop {
        if drivers.is_shutdown {
            return Err(CaliptraError::RUNTIME_SHUTDOWN);
        }

        if drivers.mbox.is_cmd_ready() {
            caliptra_drivers::report_fw_error_non_fatal(0);
            match handle_command(drivers) {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
        }
    }
}

pub fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    loop {
        while !drivers.mbox.is_cmd_ready() {
            // Wait for a request from the SoC.
        }
        let cmd = drivers.mbox.cmd();

        match cmd {
            CommandId(OPCODE_READ_RT_FW_JOURNEY) => {
                let rt_journey_pcr: [u8; 48] = drivers.pcr_bank.read_pcr(RT_FW_JOURNEY_PCR).into();
                write_response(&mut drivers.mbox, &rt_journey_pcr);
            }
            CommandId(OPCODE_READ_MBOX_PAUSER_HASH) => {
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
                write_response(&mut drivers.mbox, valid_pauser_hash.as_bytes());
            }
            CommandId(OPCODE_HASH_DPE_TCI_DATA) => {
                let mut hasher = drivers.sha384.digest_init().unwrap();
                for context in drivers.persistent_data.get().dpe.contexts {
                    if context.state != ContextState::Inactive {
                        hasher.update(context.tci.tci_current.as_bytes()).unwrap();
                    }
                }
                let mut digest = Array4x12::default();
                hasher.finalize(&mut digest).unwrap();
                write_response(&mut drivers.mbox, &<[u8; 48]>::from(digest));
            }
            CommandId(OPCODE_READ_STASHED_MEASUREMENT_PCR) => {
                let pcr_id_stash_measurement: [u8; 48] =
                    drivers.pcr_bank.read_pcr(PCR_ID_STASH_MEASUREMENT).into();
                write_response(&mut drivers.mbox, &pcr_id_stash_measurement);
            }
            CommandId(OPCODE_READ_DPE_ROOT_CONTEXT_MEASUREMENT) => {
                let root_idx =
                    Drivers::get_dpe_root_context_idx(&drivers.persistent_data.get().dpe).unwrap();
                let root_measurement = drivers.persistent_data.get().dpe.contexts[root_idx]
                    .tci
                    .tci_current
                    .as_bytes();
                write_response(&mut drivers.mbox, root_measurement);
            }
            CommandId(OPCODE_READ_DPE_TAGS) => {
                let context_tags = drivers.persistent_data.get().context_tags;
                let context_has_tag = drivers.persistent_data.get().context_has_tag;
                const CONTEXT_TAGS_SIZE: usize = MAX_HANDLES * size_of::<u32>();
                const CONTEXT_HAS_TAG_SIZE: usize = MAX_HANDLES * size_of::<U8Bool>();
                let mut tags_info = [0u8; CONTEXT_TAGS_SIZE + CONTEXT_HAS_TAG_SIZE];
                tags_info[..CONTEXT_TAGS_SIZE].copy_from_slice(context_tags.as_bytes());
                tags_info[CONTEXT_TAGS_SIZE..].copy_from_slice(context_has_tag.as_bytes());
                write_response(&mut drivers.mbox, tags_info.as_bytes());
            }
            CommandId(OPCODE_CORRUPT_CONTEXT_TAGS) => {
                let input_bytes = read_request(&drivers.mbox);

                let corrupted_context_tags = <[u32; MAX_HANDLES]>::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().context_tags = corrupted_context_tags;
                write_response(&mut drivers.mbox, &[]);
            }
            CommandId(OPCODE_CORRUPT_CONTEXT_HAS_TAG) => {
                let input_bytes = read_request(&drivers.mbox);

                let corrupted_context_has_tag =
                    <[U8Bool; MAX_HANDLES]>::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().context_has_tag = corrupted_context_has_tag;
                write_response(&mut drivers.mbox, &[]);
            }
            CommandId(OPCODE_READ_DPE_INSTANCE) => {
                write_response(
                    &mut drivers.mbox,
                    drivers.persistent_data.get().dpe.as_bytes(),
                );
            }
            CommandId(OPCODE_CORRUPT_DPE_INSTANCE) => {
                let input_bytes = read_request(&drivers.mbox);

                let corrupted_dpe = DpeInstance::read_from(input_bytes).unwrap();
                drivers.persistent_data.get_mut().dpe = corrupted_dpe;
                write_response(&mut drivers.mbox, &[]);
            }
            CommandId(OPCODE_READ_PCR_RESET_COUNTER) => {
                write_response(
                    &mut drivers.mbox,
                    drivers.persistent_data.get().pcr_reset.as_bytes(),
                );
            }
            CommandId(OPCODE_CORRUPT_DPE_ROOT_TCI) => {
                let input_bytes = read_request(&drivers.mbox);

                let root_idx =
                    Drivers::get_dpe_root_context_idx(&drivers.persistent_data.get().dpe).unwrap();
                drivers.persistent_data.get_mut().dpe.contexts[root_idx]
                    .tci
                    .tci_current = TciMeasurement(input_bytes.try_into().unwrap());
                write_response(&mut drivers.mbox, &[]);
            }
            CommandId(OPCODE_FW_LOAD) => {
                unsafe { SocIfcReg::new() }
                    .regs_mut()
                    .internal_fw_update_reset()
                    .write(|w| w.core_rst(true));
            }
            _ => {
                drivers.mbox.set_status(MboxStatusE::CmdFailure);
            }
        }
    }
}

test_suite! {
    rt_entry,
}
