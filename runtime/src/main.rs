/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra Test Runtime

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_common::cprintln;
use caliptra_cpu::TrapRecord;
use caliptra_drivers::{Ecc384, Hmac384, KeyVault, Mailbox, Sha256, Sha384, Sha384Acc, SocIfc};
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
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);
    if let Some(mut fht) = caliptra_common::FirmwareHandoffTable::try_load() {
        let mut drivers = match unsafe { Drivers::new_from_registers(&mut fht) } {
            Ok(drivers) => drivers,
            Err(e) => {
                caliptra_common::report_handoff_error_and_halt(
                    "Runtime can't load drivers",
                    e.into(),
                );
            }
        };
        cprintln!("Caliptra RT listening for mailbox commands...");
        caliptra_runtime::handle_mailbox_commands(&mut drivers);
        caliptra_drivers::ExitCtrl::exit(0)
    } else {
        caliptra_common::report_handoff_error_and_halt(
            "Runtime can't load FHT",
            caliptra_drivers::CaliptraError::RUNTIME_HANDOFF_FHT_NOT_LOADED.into(),
        );
    }
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(trap_record: &TrapRecord) {
    cprintln!(
        "RT EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc
    );

    // Signal non-fatal error to SOC
    handle_fatal_error(caliptra_drivers::CaliptraError::RUNTIME_GLOBAL_EXCEPTION.into());
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(trap_record: &TrapRecord) {
    cprintln!(
        "RT NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        trap_record.mcause,
        trap_record.mscause,
        trap_record.mepc
    );

    handle_fatal_error(caliptra_drivers::CaliptraError::RUNTIME_GLOBAL_NMI.into());
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

/// Report fatal F/W error
///
/// # Arguments
///
/// * `val` - F/W error code.
fn report_fw_error_fatal(val: u32) {
    let mut soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs_mut().cptra_fw_error_fatal().write(|_| val);
}

#[allow(clippy::empty_loop)]
fn handle_fatal_error(code: u32) -> ! {
    cprintln!("RT Fatal Error: 0x{:08X}", code);
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
