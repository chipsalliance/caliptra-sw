/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
use core::hint::black_box;

use caliptra_common::cprintln;
use caliptra_drivers::{
    report_fw_error_non_fatal, Ecc384, Hmac384, KeyVault, Mailbox, Sha256, Sha384, Sha384Acc,
    SocIfc, report_fw_error_fatal,
};
mod boot_status;
mod flow;
pub mod fmc_env;
mod hand_off;

pub use boot_status::FmcBootStatus;
use caliptra_cpu::TrapRecord;
use hand_off::HandOff;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

#[no_mangle]
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);

    if let Some(mut hand_off) = HandOff::from_previous() {
        let mut env = match unsafe { fmc_env::FmcEnv::new_from_registers() } {
            Ok(env) => env,
            Err(e) => report_error(e.into()),
        };

        match flow::run(&mut env, &mut hand_off) {
            Ok(_) => {
                if hand_off.is_valid() {
                    hand_off.to_rt(&mut env);
                }
            }
            Err(e) => report_error(e.into()),
        }
    }
    caliptra_drivers::ExitCtrl::exit(0xff)
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
    handle_fatal_error(caliptra_error::CaliptraError::FMC_GLOBAL_EXCEPTION.into());
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

    handle_fatal_error(caliptra_error::CaliptraError::FMC_GLOBAL_NMI.into());
}
#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("FMC Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC
    report_error(caliptra_error::CaliptraError::FMC_GLOBAL_PANIC.into());
}

#[allow(clippy::empty_loop)]
fn report_error(code: u32) -> ! {
    cprintln!("FMC Error: 0x{:08X}", code);
    report_fw_error_non_fatal(code);

    loop {
        // SoC firmware might be stuck waiting for Caliptra to finish
        // executing this pending mailbox transaction. Notify them that
        // we've failed.
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[allow(clippy::empty_loop)]
fn handle_fatal_error(code: u32) -> ! {
    cprintln!("RT Fatal Error: 0x{:08X}", code);
    report_fw_error_fatal(code);
    // Populate the non-fatal error code too; if there was a
    // non-fatal error stored here before we don't want somebody
    // mistakenly thinking that was the reason for their mailbox
    // command failure.
    report_fw_error_non_fatal(code);

    unsafe {
        // Zeroize the crypto blocks.
        Ecc384::zeroize();
        Hmac384::zeroize();
        Sha256::zeroize();
        Sha384::zeroize();
        Sha384Acc::zeroize();

        // Zeroize the key vault.
        KeyVault::zeroize();

        // Lock the SHA Accelerator.
        Sha384Acc::lock();

        // Stop the watchdog timer.
        // Note: This is an idempotent operation.
        SocIfc::stop_wdt1();
    }

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
