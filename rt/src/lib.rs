/*++
Licensed under the Apache-2.0 license.
File Name:
    lib.rs
Abstract:
    File contains Macros and APIs for Caliptra RISCV RT
--*/
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "riscv")]
core::arch::global_asm!(include_str!("start.S"));

#[cfg(feature = "riscv")]
use core::panic::PanicInfo;
#[cfg(feature = "riscv")]
use core::sync::atomic::{self, Ordering};

#[cfg(feature = "riscv")]
/// Registers saved in trap handler
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub ra: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
}

/// Trap entry point rust (_rust_trap_entry_)
#[link_section = ".trap.rust"]
#[export_name = "_rust_trap_entry"]
#[cfg(feature = "riscv")]
pub extern "C" fn rust_trap_entry(_trap_frame: *const TrapFrame) -> ! {
    caliptra_lib::ExitCtrl::exit(0xff);
}

#[inline(never)]
#[panic_handler]
#[cfg(feature = "riscv")]
pub fn panic(_info: &PanicInfo) -> ! {
    loop {
        atomic::compiler_fence(Ordering::SeqCst);
    }
}
