/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra Test Runtime

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(target_arch = "riscv32")]
core::arch::global_asm!(include_str!("ext_intr.S"));

use caliptra_cfi_lib_git::CfiCounter;
use caliptra_common::{cprintln, handle_fatal_error};
use caliptra_cpu::{log_trap_record, TrapRecord};
use caliptra_error::CaliptraError;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_runtime::Drivers;
use core::hint::black_box;

#[cfg(feature = "std")]
pub fn main() {}

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
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);

    #[cfg(target_arch = "riscv32")]
    unsafe {
        // Write meivt (External Interrupt Vector Table Register)
        // VeeR has been instantiated with RV_FAST_INTERRUPT_REDIRECT,
        // so external interrupts always bypass the standard risc-v dispatch logic
        // and instead load the destination address from this table in DCCM.
        core::arch::asm!(
            "la {tmp}, _ext_intr_vector",
            "csrw 0xbc8, {tmp}",
            tmp = out(reg) _,
        );
    }

    let mut drivers = unsafe {
        Drivers::new_from_registers().unwrap_or_else(|e| {
            cprintln!("[rt] Runtime can't load drivers");
            handle_fatal_error(e.into());
        })
    };
    caliptra_common::stop_wdt(&mut drivers.soc_ifc);

    if !cfg!(feature = "no-cfi") {
        cprintln!("[state] CFI Enabled");
        let mut entropy_gen = || {
            drivers
                .trng
                .generate()
                .map(|a| a.0)
                .map_err(|_| caliptra_cfi_lib_git::CfiPanicInfo::TrngError)
        };
        CfiCounter::reset(&mut entropy_gen);
        CfiCounter::reset(&mut entropy_gen);
        CfiCounter::reset(&mut entropy_gen);
    } else {
        cprintln!("[state] CFI Disabled");
    }

    if !drivers.persistent_data.get().fht.is_valid() {
        cprintln!("[rt] Runtime can't load FHT");
        handle_fatal_error(caliptra_drivers::CaliptraError::RUNTIME_HANDOFF_FHT_NOT_LOADED.into());
    }
    cprintln!("[rt] Runtime listening for mailbox commands...");
    if let Err(e) = caliptra_runtime::handle_mailbox_commands(&mut drivers) {
        handle_fatal_error(e.into());
    }
    loop {}
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(trap_record: &TrapRecord) {
    cprintln!(
        "RT EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc,
        trap_record.ra,
    );
    log_trap_record(trap_record, None);

    // Signal non-fatal error to SOC
    handle_fatal_error(caliptra_drivers::CaliptraError::RUNTIME_GLOBAL_EXCEPTION.into());
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
        "RT NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X} ra=0x{:08X} error_internal_intr_r={:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc,
        trap_record.ra,
        err_interrupt_status,
    );

    let wdt_status = soc_ifc.regs().cptra_wdt_status().read();
    let error = if wdt_status.t1_timeout() || wdt_status.t2_timeout() {
        cprintln!("[rt] WDT Expired");
        CaliptraError::RUNTIME_GLOBAL_WDT_EXPIRED
    } else {
        CaliptraError::RUNTIME_GLOBAL_NMI
    };

    handle_fatal_error(error.into());
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn runtime_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("RT Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC
    handle_fatal_error(caliptra_drivers::CaliptraError::RUNTIME_GLOBAL_PANIC.into());
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    cprintln!("RT CFI Panic code=0x{:08X}", code);

    handle_fatal_error(code);
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}
