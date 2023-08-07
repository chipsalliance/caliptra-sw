/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "val-rom"), allow(unused_imports))]

use crate::lock::lock_registers;
use core::hint::black_box;

use caliptra_drivers::{
    report_fw_error_fatal, report_fw_error_non_fatal, CaliptraError, Ecc384, Hmac384, KeyVault,
    Mailbox, ResetReason, Sha256, Sha384, Sha384Acc, SocIfc,
};
use rom_env::RomEnv;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!(concat!(
    env!("OUT_DIR"),
    "/start_preprocessed.S"
)));

mod exception;
mod fht;
#[cfg_attr(feature = "val-rom", path = "flow_val_rom.rs")]
mod flow;
mod fuse;
mod kat;
mod lock;
mod pcr;
mod print;
mod rom_env;
#[cfg_attr(feature = "val-rom", path = "verifier_val_rom.rs")]
mod verifier;
mod wdt;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra ROM ...
"#;

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    cprintln!("{}", BANNER);

    let mut env = match unsafe { rom_env::RomEnv::new_from_registers() } {
        Ok(env) => env,
        Err(e) => handle_fatal_error(e.into()),
    };

    let _lifecyle = match env.soc_ifc.lifecycle() {
        caliptra_drivers::Lifecycle::Unprovisioned => "Unprovisioned",
        caliptra_drivers::Lifecycle::Manufacturing => "Manufacturing",
        caliptra_drivers::Lifecycle::Production => "Production",
        caliptra_drivers::Lifecycle::Reserved2 => "Unknown",
    };
    cprintln!("[state] LifecycleState = {}", _lifecyle);

    if cfg!(feature = "val-rom")
        && env.soc_ifc.lifecycle() == caliptra_drivers::Lifecycle::Production
    {
        cprintln!("Val ROM in Production lifecycle prohibited");
        handle_fatal_error(CaliptraError::ROM_GLOBAL_VAL_ROM_IN_PRODUCTION.into());
    }

    cprintln!(
        "[state] DebugLocked = {}",
        if env.soc_ifc.debug_locked() {
            "Yes"
        } else {
            "No"
        }
    );

    // Start the watchdog timer
    wdt::start_wdt(&mut env.soc_ifc);

    if !cfg!(feature = "val-rom") {
        let result = kat::execute_kat(&mut env);
        if let Err(err) = result {
            handle_fatal_error(err.into());
        }
    }

    let reset_reason = env.soc_ifc.reset_reason();

    let result = flow::run(&mut env);
    match result {
        Ok(Some(fht)) => {
            fht::store(fht);
        }
        Ok(None) => {}
        Err(err) => {
            //
            // For the update reset case, when we fail the image validation
            // we will need to continue to jump to the FMC after
            // reporting the error in the registers.
            //
            if reset_reason == ResetReason::UpdateReset {
                handle_non_fatal_error(err.into());
            } else {
                handle_fatal_error(err.into());
            }
        }
    }

    // Stop the watchdog timer.
    // [TODO] Reset the watchdog timer and let FMC take ownership of it.
    wdt::stop_wdt(&mut env.soc_ifc);

    // Lock the datavault registers.
    lock_registers(&mut env, reset_reason);

    #[cfg(not(feature = "no-fmc"))]
    launch_fmc(&mut env);

    #[cfg(feature = "no-fmc")]
    caliptra_drivers::ExitCtrl::exit(0);
}

fn launch_fmc(env: &mut RomEnv) -> ! {
    // Function is defined in start.S
    extern "C" {
        fn exit_rom(entry: u32) -> !;
    }

    // Get the fmc entry point from data vault
    let entry = env.data_vault.fmc_entry_point();

    cprintln!("[exit] Launching FMC @ 0x{:08X}", entry);

    // Exit ROM and jump to specified entry point
    unsafe { exit_rom(entry) }
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    // TODO: Signal non-fatal error to SOC

    handle_fatal_error(CaliptraError::ROM_GLOBAL_EXCEPTION.into());
}

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    // TODO: Signal error to SOC
    // - Signal Fatal error for ICCM/DCCM double bit faults
    // - Signal Non=-Fatal error for all other errors

    handle_fatal_error(CaliptraError::ROM_GLOBAL_NMI.into());
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn rom_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC
    handle_fatal_error(CaliptraError::ROM_GLOBAL_PANIC.into());
}

fn handle_non_fatal_error(code: u32) {
    cprintln!("ROM Non-Fatal Error: 0x{:08X}", code);
    report_fw_error_non_fatal(code);
}

#[allow(clippy::empty_loop)]
fn handle_fatal_error(code: u32) -> ! {
    cprintln!("ROM Fatal Error: 0x{:08X}", code);
    report_fw_error_fatal(code);

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
