/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra Test Runtime

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(feature = "interactive_test", allow(unused_imports))]
mod interactive_test;

use caliptra_common::cprintln;
use caliptra_cpu::TrapRecord;
use caliptra_drivers::{report_fw_error_non_fatal, Mailbox, PcrBank, PersistentDataAccessor};
use caliptra_registers::pv::PvReg;
use core::hint::black_box;

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
    let persistent_data = unsafe { PersistentDataAccessor::new() };

    if !persistent_data.get().fht.is_valid() {
        cprintln!("FHT not loaded");
        caliptra_drivers::ExitCtrl::exit(0xff)
    }
    // Test PCR is locked.
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    // Test erasing pcr. This should fail.
    assert!(pcr_bank
        .erase_pcr(caliptra_common::RT_FW_CURRENT_PCR)
        .is_err());
    assert!(pcr_bank
        .erase_pcr(caliptra_common::RT_FW_JOURNEY_PCR)
        .is_err());

    if cfg!(feature = "interactive_test") {
        interactive_test::process_mailbox_commands();
    }
    caliptra_drivers::ExitCtrl::exit(0)
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
