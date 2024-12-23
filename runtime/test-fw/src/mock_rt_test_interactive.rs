// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use caliptra_common::{handle_fatal_error, mailbox_api::CommandId};
use caliptra_drivers::pcr_log::{PcrLogEntry, PcrLogEntryId};

use caliptra_drivers::{cprintln, CaliptraError, CaliptraResult};
use caliptra_drivers::{PcrBank, PcrId, PersistentDataAccessor};
use caliptra_registers::pv::PvReg;
use caliptra_registers::{mbox::enums::MboxStatusE, soc_ifc::SocIfcReg};
use caliptra_runtime::{mailbox::Mailbox, Drivers, RtBootStatus};
use caliptra_test_harness::{runtime_handlers, test_suite};
use zerocopy::AsBytes;

const OPCODE_FW_LOAD: u32 = CommandId::FIRMWARE_LOAD.0;

const BANNER: &str = r#"FMC Tester"#;

pub const TEST_CMD_READ_PCR_LOG: u32 = 0x1000_0000;
pub const TEST_CMD_READ_FHT: u32 = 0x1000_0001;
pub const TEST_CMD_READ_PCRS: u32 = 0x1000_0002;
pub const TEST_CMD_PCRS_LOCKED: u32 = 0x1000_0004;

#[no_mangle]
#[allow(clippy::empty_loop)]
fn rt_entry() {
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
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) -> CaliptraResult<()> {
    // Indicator to SOC that RT firmware is ready
    drivers.soc_ifc.assert_ready_for_runtime();
    caliptra_drivers::report_boot_status(RtBootStatus::RtReadyForCommands.into());

    let persistent_data = unsafe { PersistentDataAccessor::new() };

    loop {
        if drivers.is_shutdown {
            return Err(CaliptraError::RUNTIME_SHUTDOWN);
        }

        if drivers.mbox.is_cmd_ready() {
            caliptra_drivers::report_fw_error_non_fatal(0);
            match handle_command(drivers, &persistent_data) {
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

pub fn handle_command(
    drivers: &mut Drivers,
    persistent_data: &PersistentDataAccessor,
) -> CaliptraResult<MboxStatusE> {
    loop {
        while !drivers.mbox.is_cmd_ready() {
            // Wait for a request from the SoC.
        }
        let cmd = drivers.mbox.cmd();
        let mbox = &mut drivers.mbox;

        match cmd {
            CommandId(OPCODE_FW_LOAD) => trigger_update_reset(),
            CommandId(TEST_CMD_READ_PCR_LOG) => read_pcr_log(persistent_data, mbox),
            CommandId(TEST_CMD_READ_FHT) => read_fht(persistent_data, mbox),
            CommandId(TEST_CMD_READ_PCRS) => read_pcrs(mbox),
            CommandId(TEST_CMD_PCRS_LOCKED) => try_to_reset_pcrs(mbox),
            _ => {
                drivers.mbox.set_status(MboxStatusE::CmdFailure);
            }
        }
    }
}

fn read_pcr_log(persistent_data: &PersistentDataAccessor, mbox: &mut Mailbox) {
    let mut pcr_entry_count = 0;
    loop {
        let pcr_entry = persistent_data.get().pcr_log[pcr_entry_count];
        if PcrLogEntryId::from(pcr_entry.id) == PcrLogEntryId::Invalid {
            break;
        }

        pcr_entry_count += 1;
        mbox.copy_bytes_to_mbox(pcr_entry.as_bytes()).unwrap();
    }

    mbox.set_dlen(
        (core::mem::size_of::<PcrLogEntry>() * pcr_entry_count)
            .try_into()
            .unwrap(),
    )
    .unwrap();
    mbox.set_status(MboxStatusE::DataReady);
}

fn read_fht(persistent_data: &PersistentDataAccessor, mbox: &mut Mailbox) {
    mbox.write_response(persistent_data.get().fht.as_bytes())
        .unwrap();
    mbox.set_status(MboxStatusE::DataReady);
}

fn read_pcrs(mbox: &mut Mailbox) {
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    const PCR_COUNT: usize = 32;
    for i in 0..PCR_COUNT {
        let pcr = pcr_bank.read_pcr(PcrId::try_from(i as u8).unwrap());
        let mut pcr_bytes: [u32; 12] = pcr.into();

        swap_word_bytes_inplace(&mut pcr_bytes);
        mbox.copy_bytes_to_mbox(pcr.as_bytes()).unwrap();
    }
    mbox.set_dlen((48 * PCR_COUNT).try_into().unwrap()).unwrap();
    mbox.set_status(MboxStatusE::DataReady);
}

fn swap_word_bytes_inplace(words: &mut [u32]) {
    for word in words.iter_mut() {
        *word = word.swap_bytes()
    }
}

fn try_to_reset_pcrs(mbox: &mut Mailbox) {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    let res0 = pcr_bank.erase_pcr(caliptra_common::RT_FW_CURRENT_PCR);
    let res1 = pcr_bank.erase_pcr(caliptra_common::RT_FW_JOURNEY_PCR);

    // Resetting the PCRs should fail if locked
    if res0.is_err() && res1.is_err() {
        mbox.set_status(MboxStatusE::CmdComplete);
    } else {
        mbox.set_status(MboxStatusE::CmdFailure);
    }
}

fn trigger_update_reset() {
    unsafe { SocIfcReg::new() }
        .regs_mut()
        .internal_fw_update_reset()
        .write(|w| w.core_rst(true));
}

test_suite! {
    rt_entry,
}
