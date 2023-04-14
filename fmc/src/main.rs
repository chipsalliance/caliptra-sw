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
use caliptra_drivers::report_fw_error_non_fatal;
mod flow;
pub mod fmc_env;
pub mod fmc_env_cell;
mod hand_off;

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
        let env = fmc_env::FmcEnv::default();
        if flow::run(&env, &mut hand_off).is_ok() {
            hand_off.to_rt(&env)
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

    // TODO: Signal error to SOC
    // - Signal Fatal error for ICCM/DCCM double bit faults
    // - Signal Non=-Fatal error for all other errors
    report_error(0xdead);
}
#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("FMC Panic!!");
    panic_is_possible();

    // TODO: Signal non-fatal error to SOC
    report_error(0xdead);
}

#[allow(clippy::empty_loop)]
fn report_error(code: u32) -> ! {
    cprintln!("FMC Error: 0x{:08X}", code);
    report_fw_error_non_fatal(code);

    loop {}
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}
