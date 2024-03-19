/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    File contains main entry point for Caliptra Test Runtime

--*/
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use caliptra_drivers::Mailbox;

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("start.S"));

mod exception;
mod print;

#[cfg(feature = "std")]
pub fn main() {}

// Dummy RO data to max out FW image size.
static PAD: [u32; 26754] = {
    let mut result = [0xba5eba11_u32; 26754];
    let mut i = 0;
    while i < result.len() {
        result[i] = result[i].wrapping_add(i as u32);
        i += 1;
    }
    result
};

const BANNER: &str = r#"
  ____      _ _       _               ____ _____
 / ___|__ _| (_)_ __ | |_ _ __ __ _  |  _ \_   _|
| |   / _` | | | '_ \| __| '__/ _` | | |_) || |
| |__| (_| | | | |_) | |_| | | (_| | |  _ < | |
 \____\__,_|_|_| .__/ \__|_|  \__,_| |_| \_\|_|
               |_|
"#;

#[no_mangle]
pub extern "C" fn rt_entry() -> ! {
    cprintln!("{}", BANNER);

    for (x, item) in PAD.iter().enumerate() {
        cprint!("PAD[{}] = 0x{:08X}", x, *item);
    }

    caliptra_drivers::ExitCtrl::exit(0)
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "RT EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[no_mangle]
#[inline(never)]
#[allow(clippy::empty_loop)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "RT NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );

    loop {
        unsafe { Mailbox::abort_pending_soc_to_uc_transactions() };
    }
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
#[allow(clippy::empty_loop)]
fn fmc_panic(_: &core::panic::PanicInfo) -> ! {
    cprintln!("RT Panic!!");
    loop {}
}
