// Licensed under the Apache-2.0 license

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

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

extern "C" {
    fn _zero_mem256(dest: *mut u32, len: usize);
}

#[no_mangle]
#[cfg(not(feature = "std"))]
pub extern "C" fn rom_entry() -> ! {
    unsafe {
        core::arch::asm!(
            "li x28, 1",
            "csrrw zero, mseccfg, x28", // set machine lock mode
            "li x28, 0x14000000", // 0x5000_0000 - 0x5000_0003
            "csrrw zero, pmpaddr0, x28",
            "li x28, 0x90", // lock out region in M-mode, naturally aligned power of 2 region >= 8 bytes
            "csrrw zero, pmpcfg0, x28",
            lateout("x28") _,
        );
        // this should trigger an exception
        _zero_mem256(0x5000_0000 as *mut u32, 1);
    }
    ExitCtrl::exit(0)
}
