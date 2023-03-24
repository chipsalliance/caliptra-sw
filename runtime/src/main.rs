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

    if let Some(fht) = caliptra_common::FirmwareHandoffTable::try_load() {
        cprintln!("[rt] FHT Marker: 0x{:08X}", fht.fht_marker);
        cprintln!("[rt] FHT Major Version: 0x{:04X}", fht.fht_major_ver);
        cprintln!("[rt] FHT Minor Version: 0x{:04X}", fht.fht_minor_ver);
        cprintln!("[rt] FHT Manifest Addr: 0x{:08X}", fht.manifest_load_addr);
        cprintln!("[rt] FHT FMC CDI KV KeyID: {}", fht.fmc_cdi_kv_idx);
        cprintln!("[rt] FHT FMC PrivKey KV KeyID: {}", fht.fmc_priv_key_kv_idx);
        cprintln!("[rt] FHT RT Load Address: 0x{:08x}", fht.rt_fw_load_addr);
        cprintln!("[rt] FHT RT Entry Point: 0x{:08x}", fht.rt_fw_load_addr);
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
    cprintln!("RT Panic!!");

    // TODO: Signal non-fatal error to SOC

    loop {}
}
