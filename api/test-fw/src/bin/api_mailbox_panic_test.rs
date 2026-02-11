// Licensed under the Apache-2.0 license

//! Minimal RISC-V binary that calls caliptra-api mailbox functions.
//!
//! This binary is not meant to be executed; it exists solely so that the
//! test_panic_missing integration test can build it for riscv32imc and
//! inspect the resulting ELF for panic-related symbols.
//!
//! It defines a panic handler containing a `panic_is_possible` sentinel
//! symbol. If any code linked into this binary can panic, the compiler
//! will keep the panic handler and the sentinel will appear in the ELF.

#![no_std]
#![no_main]

use caliptra_api::mailbox::StashMeasurementReq;
use caliptra_api::SocManager;
use core::hint::black_box;
use core::panic::PanicInfo;
use ureg::RealMmioMut;

// Force the test harness to be linked, which provides start.S.
extern crate caliptra_test_harness;

#[panic_handler]
#[inline(never)]
fn panic_handler(_: &PanicInfo) -> ! {
    panic_is_possible();
    loop {}
}

#[no_mangle]
#[inline(never)]
fn panic_is_possible() {
    black_box(());
    // The existence of this symbol is used to inform test_panic_missing
    // that panics are possible. Do not remove or rename this symbol.
}

#[no_mangle]
extern "C" fn cfi_panic_handler(_code: u32) -> ! {
    loop {}
}

/// A minimal SocManager implementation for compilation purposes.
struct TestSocManager;

impl SocManager for TestSocManager {
    const SOC_MBOX_ADDR: u32 = 0x3002_0000;
    const SOC_SHA512_ACC_ADDR: u32 = 0x3002_1000;
    const SOC_IFC_ADDR: u32 = 0x3003_0000;
    const SOC_IFC_TRNG_ADDR: u32 = 0x3003_0000;
    const MAX_WAIT_CYCLES: u32 = 400_000;

    type TMmio<'a> = RealMmioMut<'a>;

    fn mmio_mut(&mut self) -> Self::TMmio<'_> {
        RealMmioMut::default()
    }

    fn delay(&mut self) {}
}

/// Calls mailbox_exec_req to ensure it is linked into the binary.
fn test_mailbox_exec_req_linked() {
    let mut mgr = TestSocManager;
    let req = StashMeasurementReq::default();
    let mut resp_bytes = [0u8; 512];
    // We don't care about the result; the point is that the compiler
    // must link in the full mailbox_exec_req code path, including any
    // .unwrap() calls that may introduce panics.
    let _ = black_box(mgr.mailbox_exec_req(req, &mut resp_bytes));
}

/// Calls mailbox_exec (the untyped version) to cover that code path too.
fn test_mailbox_exec_linked() {
    let mut mgr = TestSocManager;
    let mut resp_bytes = [0u8; 512];
    let _ = black_box(mgr.mailbox_exec(0x4d454153, &[0u8; 8], &mut resp_bytes));
}

#[no_mangle]
pub extern "C" fn main() {
    test_mailbox_exec_req_linked();
    test_mailbox_exec_linked();
}

#[no_mangle]
pub extern "C" fn entry_point() {
    main();
    caliptra_drivers::ExitCtrl::exit(0);
}
