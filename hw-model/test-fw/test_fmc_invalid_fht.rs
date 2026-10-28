// Licensed under the Apache-2.0 license

#![no_main]
#![no_std]

use caliptra_drivers::{
    memory_layout::ICCM_ORG, report_boot_status, report_fw_error_non_fatal, CaliptraError,
    PersistentDataAccessor, RomPersistentData, SocIfc,
};
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::println;

#[no_mangle]
extern "C" fn main() {
    let mut persistent_data = unsafe { PersistentDataAccessor::new() };
    let rom = &mut persistent_data.get_mut().rom;
    rom.marker = RomPersistentData::MAGIC;
    rom.major_version = RomPersistentData::MAJOR_VERSION;
    rom.minor_version = RomPersistentData::MINOR_VERSION;

    let mut soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    soc_ifc.set_wdt1_timeout(20_000_000);
    unsafe { SocIfcReg::new() }
        .regs_mut()
        .cptra_wdt_timer1_en()
        .write(|w| w.timer1_en(true));
    report_fw_error_non_fatal(CaliptraError::FMC_HANDOFF_NOT_READY_FOR_RT.into());
    println!("Launching FMC with invalid FHT");
    report_boot_status(0xf000_0000);

    let entry: extern "C" fn() -> ! = unsafe { core::mem::transmute(ICCM_ORG as usize) };
    entry();
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    caliptra_drivers::ExitCtrl::exit(1)
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    caliptra_drivers::report_fw_error_fatal(code);
    caliptra_drivers::ExitCtrl::exit(1)
}
