/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra Test Runtime

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_common::memory_layout::PCR_LOG_ORG;
use caliptra_common::FirmwareHandoffTable;
use caliptra_common::PcrLogEntry;
use caliptra_common::FHT_ORG;
use caliptra_common::{cprintln, PcrLogEntryId};
use caliptra_cpu::TrapRecord;
use caliptra_drivers::Mailbox;
use caliptra_drivers::{report_fw_error_non_fatal, PcrBank};
use caliptra_registers::pv::PvReg;
use core::hint::black_box;
use ureg::RealMmioMut;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
   _____                 __     __________   __   
  /     \   ____   ____ |  | __ \______   \_/  |_ 
 /  \ /  \ /  _ \_/ ___\|  |/ /  |       _/\   __\
/    Y    (  <_> )  \___|    <   |    |   \ |  |  
\____|__  /\____/ \___  >__|_ \  |____|_  / |__|  
        \/            \/     \/         \/       
"#;

#[no_mangle]
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);

    if let Some(_fht) = caliptra_common::FirmwareHandoffTable::try_load() {
        // Test PCR is locked.
        let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
        // Test erasing pcr. This should fail.
        assert!(pcr_bank
            .erase_pcr(caliptra_common::RT_FW_CURRENT_PCR)
            .is_err());
        assert!(pcr_bank
            .erase_pcr(caliptra_common::RT_FW_JOURNEY_PCR)
            .is_err());

        process_mailbox_commands();

        caliptra_drivers::ExitCtrl::exit(0)
    } else {
        cprintln!("FHT not loaded");
        caliptra_drivers::ExitCtrl::exit(0xff)
    }
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(trap_record: &TrapRecord) {
    cprintln!(
        "FMC EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc
    );

    // Signal non-fatal error to SOC
    report_error(0xdead);
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(trap_record: &TrapRecord) {
    cprintln!(
        "FMC NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc
    );

    report_error(0xdead);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("RT Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC
    report_error(0xdead);
}

#[allow(clippy::empty_loop)]
fn report_error(code: u32) -> ! {
    cprintln!("RT Error: 0x{:08X}", code);
    report_fw_error_non_fatal(code);
    loop {
        // SoC firmware might be stuck waiting for Caliptra to finish
        // executing this pending mailbox transaction. Notify them that
        // we've failed.
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}
fn read_pcr_log(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let mut pcr_entry_count = 0;
    loop {
        let pcr_entry = get_pcr_entry(pcr_entry_count);
        if PcrLogEntryId::from(pcr_entry.id) == PcrLogEntryId::Invalid {
            break;
        }

        pcr_entry_count += 1;
        send_to_mailbox(mbox, pcr_entry.as_bytes(), false);
    }

    mbox.dlen().write(|_| {
        (core::mem::size_of::<PcrLogEntry>() * pcr_entry_count)
            .try_into()
            .unwrap()
    });
    mbox.status().write(|w| w.status(|w| w.data_ready()));
}

fn get_pcr_entry(entry_index: usize) -> PcrLogEntry {
    // Copy the pcr log entry from DCCM
    let mut pcr_entry: [u8; core::mem::size_of::<PcrLogEntry>()] =
        [0u8; core::mem::size_of::<PcrLogEntry>()];

    let src = unsafe {
        let offset = core::mem::size_of::<PcrLogEntry>() * entry_index;
        let ptr = (PCR_LOG_ORG as *mut u8).add(offset);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<PcrLogEntry>())
    };

    pcr_entry.copy_from_slice(src);
    PcrLogEntry::read_from_prefix(pcr_entry.as_bytes()).unwrap()
}

fn read_fht(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    // Copy the FHT from DCCM
    let mut fht: [u8; core::mem::size_of::<FirmwareHandoffTable>()] =
        [0u8; core::mem::size_of::<FirmwareHandoffTable>()];

    let src = unsafe {
        let ptr = FHT_ORG as *mut u8;
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<FirmwareHandoffTable>())
    };

    fht.copy_from_slice(src);

    send_to_mailbox(mbox, fht.as_bytes(), true);
}

fn process_mailbox_command(mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>) {
    let cmd = mbox.cmd().read();
    cprintln!("[fmc] Received command: 0x{:08X}", cmd);
    match cmd {
        0x1000_0000 => {
            read_pcr_log(mbox);
        }
        0x1000_0003 => {
            read_fht(mbox);
        }
        _ => {}
    }
}

fn send_to_mailbox(
    mbox: &caliptra_registers::mbox::RegisterBlock<RealMmioMut>,
    data: &[u8],
    update_mb_state: bool,
) {
    let data_len = data.len();
    let word_size = core::mem::size_of::<u32>();
    let remainder = data_len % word_size;
    let n = data_len - remainder;
    for idx in (0..n).step_by(word_size) {
        mbox.datain()
            .write(|_| u32::from_le_bytes(data[idx..idx + word_size].try_into().unwrap()));
    }

    if remainder > 0 {
        let mut last_word = data[n] as u32;
        for idx in 1..remainder {
            last_word |= (data[n + idx] as u32) << (idx << 3);
        }
        mbox.datain().write(|_| last_word);
    }

    if update_mb_state {
        mbox.dlen().write(|_| data_len as u32);
        mbox.status().write(|w| w.status(|w| w.data_ready()));
    }
}

fn process_mailbox_commands() {
    let mut mbox = unsafe { caliptra_registers::mbox::MboxCsr::new() };
    let mbox = mbox.regs_mut();

    #[cfg(feature = "interactive_test_fmc")]
    loop {
        if mbox.status().read().mbox_fsm_ps().mbox_execute_uc() {
            process_mailbox_command(&mbox);
        }
    }

    #[cfg(not(feature = "interactive_test_fmc"))]
    process_mailbox_command(&mbox);
}
