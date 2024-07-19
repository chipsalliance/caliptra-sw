// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

core::arch::global_asm!(include_str!("start_min.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::cprintln;
use caliptra_drivers::ExitCtrl;

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    ExitCtrl::exit(1);
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

    ExitCtrl::exit(1);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn handle_panic(pi: &core::panic::PanicInfo) -> ! {
    match pi.location() {
        Some(loc) => cprintln!("Panic at file {} line {}", loc.file(), loc.line()),
        _ => {}
    }
    ExitCtrl::exit(1);
}

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    let mut soc_ifc = unsafe { caliptra_registers::soc_ifc::SocIfcReg::new() };

    let fuse_wr_done: u32 = soc_ifc.regs_mut().cptra_fuse_wr_done().read().into();
    let valid_pauser: u32 = soc_ifc
        .regs_mut()
        .cptra_mbox_valid_pauser()
        .at(0)
        .read()
        .into();
    let fuse_life_cycle: u32 = soc_ifc.regs_mut().fuse_life_cycle().read().into();

    // Print some registers populated by SoC
    cprintln!("FUSE_WR_DONE = {}", fuse_wr_done);
    cprintln!("VALID_PAUSER[0] = {}", valid_pauser);
    cprintln!("FUSE_LIFE_CYCLE = {}", fuse_life_cycle);

    // Write to some registers read by SoC
    soc_ifc.regs_mut().cptra_boot_status().write(|_| 0xff);

    ExitCtrl::exit(0)
}
