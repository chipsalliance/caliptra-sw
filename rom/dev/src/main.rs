/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use crate::lock::lock_registers;
use core::hint::black_box;

use caliptra_drivers::{caliptra_err_def, report_fw_error_non_fatal, Mailbox};
use rom_env::RomEnv;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

mod exception;
mod fht;
mod flow;
mod kat;
mod lock;
mod pcr;
mod print;
mod rom_env;
mod verifier;

caliptra_err_def! {
    RomGlobal,
    GlobalErr
    {
        Nmi= 0x1,
        Exception= 0x2,
        Panic = 0x3,
    }
}

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra ROM ...
"#;

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    cprintln!("{}", BANNER);

    let mut env = rom_env::RomEnv::default();

    let _lifecyle = match env.soc_ifc.lifecycle() {
        caliptra_drivers::Lifecycle::Unprovisioned => "Unprovisioned",
        caliptra_drivers::Lifecycle::Manufacturing => "Manufacturing",
        caliptra_drivers::Lifecycle::Production => "Production",
        caliptra_drivers::Lifecycle::Unknown => "Unknown",
    };
    cprintln!("[state] LifecycleState = {}", _lifecyle);

    cprintln!(
        "[state] DebugLocked = {}",
        if env.soc_ifc.debug_locked() {
            "Yes"
        } else {
            "No"
        }
    );

    let result = kat::execute_kat(&mut env);
    if let Err(err) = result {
        report_error(err.into());
    }

    let result = flow::run(&mut env);
    match result {
        Ok(fht) => {
            // Lock the datavault registers.
            let reset_reason = env.soc_ifc.reset_reason();
            lock_registers(&mut env, reset_reason);

            fht::load_fht(fht);
        }
        Err(err) => report_error(err.into()),
    }

    #[cfg(not(feature = "no-fmc"))]
    launch_fmc(&env);

    #[cfg(feature = "no-fmc")]
    caliptra_drivers::ExitCtrl::exit(0);
}

fn launch_fmc(env: &RomEnv) -> ! {
    // Function is defined in start.S
    extern "C" {
        fn exit_rom(entry: u32) -> !;
    }

    // Get the fmc entry point from data vault
    let entry = env.data_vault.fmc_entry_point();

    cprintln!("[exit] Launching FMC @ 0x{:08X}", entry);

    // Exit ROM and jump to speicified entry point
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

    report_error(GlobalErr::Exception.into());
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

    report_error(GlobalErr::Nmi.into());
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn rom_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC

    report_error(GlobalErr::Panic.into());
}

#[allow(clippy::empty_loop)]
fn report_error(code: u32) -> ! {
    cprintln!("ROM Error: 0x{:08X}", code);
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
