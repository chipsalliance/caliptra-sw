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

use caliptra_cfi_lib::CfiCounter;
use caliptra_common::{cprintln, handle_fatal_error};
use caliptra_cpu::{log_trap_record, TrapRecord};

use caliptra_drivers::{report_fw_error_non_fatal, Mailbox};
mod boot_status;
mod flow;
pub mod fmc_env;
mod hand_off;

pub use boot_status::FmcBootStatus;
use caliptra_error::CaliptraError;
use caliptra_registers::soc_ifc::SocIfcReg;
use hand_off::HandOff;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

// Upon cold reset, fills the reserved field with 0xFFs. Any newly-allocated fields will
// therefore be marked as implicitly invalid.
fn fix_fht(env: &mut fmc_env::FmcEnv) {
    if env.soc_ifc.reset_reason() == caliptra_drivers::ResetReason::ColdReset {
        env.persistent_data.get_mut().fht.reserved.fill(0xFF);
    }
}

#[no_mangle]
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);
    let mut env = match unsafe { fmc_env::FmcEnv::new_from_registers() } {
        Ok(env) => env,
        Err(e) => report_error(e.into()),
    };

    if !cfg!(feature = "no-cfi") {
        cprintln!("[state] CFI Enabled");
        let mut entropy_gen = || env.trng.generate().map(|a| a.0);
        CfiCounter::reset(&mut entropy_gen);
    } else {
        cprintln!("[state] CFI Disabled");
    }

    fix_fht(&mut env);

    if env.persistent_data.get().fht.is_valid() {
        // Jump straight to RT for val-FMC for now
        if cfg!(feature = "fake-fmc") {
            HandOff::to_rt(&env);
        }
        match flow::run(&mut env) {
            Ok(_) => match HandOff::is_ready_for_rt(&env) {
                Ok(()) => HandOff::to_rt(&env),
                Err(e) => report_error(e.into()),
            },
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
    log_trap_record(trap_record, None);

    handle_fatal_error(caliptra_error::CaliptraError::FMC_GLOBAL_EXCEPTION.into());
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(trap_record: &TrapRecord) {
    let soc_ifc = unsafe { SocIfcReg::new() };

    // If the NMI was fired by caliptra instead of the uC, this register
    // contains the reason(s)
    let err_interrupt_status = u32::from(
        soc_ifc
            .regs()
            .intr_block_rf()
            .error_internal_intr_r()
            .read(),
    );
    log_trap_record(trap_record, Some(err_interrupt_status));
    cprintln!(
        "FMC NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}error_internal_intr_r={:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc,
        err_interrupt_status,
    );
    let mut error = CaliptraError::FMC_GLOBAL_NMI;

    let wdt_status = soc_ifc.regs().cptra_wdt_status().read();
    if wdt_status.t1_timeout() || wdt_status.t2_timeout() {
        cprintln!("WDT Expired");
        error = CaliptraError::FMC_GLOBAL_WDT_EXPIRED;
    }

    handle_fatal_error(error.into());
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    cprintln!("[FMC] CFI Panic code=0x{:08X}", code);

    handle_fatal_error(code);
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

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}
