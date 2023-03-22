/*++
Licensed under the Apache-2.0 license.
File Name:
    main.rs
Abstract:
    File contains main entry point for Caliptra ROM Test FMC
--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));
#[macro_use]
extern crate caliptra_common;

use caliptra_common::hand_off::FirmwareHandoffTable;

use caliptra_cpu::trap::TrapRecord;

//use caliptra_cpu::{cprintln, exception, MutablePrinter};

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
  ____      _ _       _               _____ __  __  ____
 / ___|__ _| (_)_ __ | |_ _ __ __ _  |  ___|  \/  |/ ___|
| |   / _` | | | '_ \| __| '__/ _` | | |_  | |\/| | |
| |__| (_| | | | |_) | |_| | | (_| | |  _| | |  | | |___
 \____\__,_|_|_| .__/ \__|_|  \__,_| |_|   |_|  |_|\____|
               |_|
"#;

#[no_mangle]
pub extern "C" fn fmc_entry() -> ! {
    cprintln!("{}", BANNER);

    if let Some(_fht) = FirmwareHandoffTable::try_load() {
        caliptra_lib::ExitCtrl::exit(0)
    } else {
        caliptra_lib::ExitCtrl::exit(0xff)
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
    caliptra_lib::report_fw_error_non_fatal(0xdead0);

    loop {}
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

    loop {}
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("FMC Panic!!");

    // TODO: Signal non-fatal error to SOC

    loop {}
}
