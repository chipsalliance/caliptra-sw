/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra ROM Test FMC

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("transfer_control.S"));

use caliptra_common::{cprintln, FirmwareHandoffTable};
pub mod fmc_env;
pub mod fmc_env_cell;

use caliptra_cpu::TrapRecord;
use fmc_env::FmcEnv;

#[cfg(feature = "std")]
pub fn main() {}

const BANNER: &str = r#"
Running Caliptra FMC ...
"#;

#[no_mangle]
pub extern "C" fn entry_point() -> ! {
    cprintln!("{}", BANNER);

    if let Some(fht) = FirmwareHandoffTable::try_load() {
        cprintln!("[fmc] FHT Marker: 0x{:08X}", fht.fht_marker);
        cprintln!("[fmc] FHT Major Version: 0x{:04X}", fht.fht_major_ver);
        cprintln!("[fmc] FHT Minor Version: 0x{:04X}", fht.fht_minor_ver);
        cprintln!("[fmc] FHT Manifest Addr: 0x{:08X}", fht.manifest_load_addr);
        cprintln!("[fmc] FHT FMC CDI KV KeyID: {}", fht.fmc_cdi_kv_idx);
        cprintln!(
            "[fmc] FHT FMC PrivKey KV KeyID: {}",
            fht.fmc_priv_key_kv_idx
        );
        cprintln!(
            "[fmc] FHT RT Load Address: 0x{:08x}",
            fht.rt_fw_load_addr_idx
        );
        cprintln!(
            "[fmc] FHT RT Entry Point: 0x{:08x}",
            fht.rt_fw_load_addr_idx
        );

        let env = fmc_env::FmcEnv::default();
        launch_rt(&env)
    } else {
        caliptra_drivers::ExitCtrl::exit(0xff)
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
    caliptra_drivers::report_fw_error_non_fatal(0xdead0);

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

fn launch_rt(env: &FmcEnv) -> ! {
    // Function is defined in start.S
    extern "C" {
        fn transfer_control(entry: u32) -> !;
    }

    // Get the fmc entry point from data vault
    let entry = env.data_vault().map(|d| d.rt_entry_point());

    cprintln!("[exit] Launching RT @ 0x{:08X}", entry);

    // Exit ROM and jump to speicified entry point
    unsafe { transfer_control(entry) }
}
