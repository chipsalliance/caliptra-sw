/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_common::FirmwareHandoffTable;
use zerocopy::FromBytes;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

mod exception;
mod print;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

#[no_mangle]
pub extern "C" fn fmc_entry() -> ! {
    cprintln!("{}", BANNER);

    extern "C" {
        static mut FHT_ORG: u8;
    }

    let slice = unsafe {
        let ptr = &mut FHT_ORG as *mut u8;
        cprintln!("[fmc] Loading FHT from 0x{:08X}", ptr as u32);
        core::slice::from_raw_parts_mut(ptr, core::mem::size_of::<FirmwareHandoffTable>())
    };

    let fht = FirmwareHandoffTable::read_from(slice).unwrap();

    cprintln!("[fmc] FHT Marker: 0x{:08X}", fht.fht_marker);
    cprintln!("[fmc] FHT Major Version: 0x{:04X}", fht.fht_major_ver);
    cprintln!("[fmc] FHT Minor Version: 0x{:04X}", fht.fht_minor_ver);
    cprintln!("[fmc] FHT Manifest Addr: 0x{:08X}", fht.manifest_load_addr);
    cprintln!("[fmc] FHT FMC CDI KV KeyID: {}", fht.fmc_cdi_kv_idx);
    cprintln!(
        "[fmc] FHT FMC PrivKey KV KeyID: {}",
        fht.fmc_priv_key_kv_idx
    );
    cprintln!("[fmc] FHT RT Load Address: 0x{:08x}", fht.rt_fw_load_addr);
    cprintln!("[fmc] FHT RT Entry Point: 0x{:08x}", fht.rt_fw_load_addr);

    caliptra_drivers::ExitCtrl::exit(0)
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    // TODO: Signal non-fatal error to SOC

    loop {}
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "FMC NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
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
