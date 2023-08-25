/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_common::start_wdt;
use caliptra_common::WdtTimeout;
use caliptra_runtime::Drivers;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_wdt_timeout() {
    let fht = caliptra_common::FirmwareHandoffTable::default();
    let mut drivers = unsafe { Drivers::new_from_registers(&fht).unwrap() };

    start_wdt(&mut drivers.soc_ifc, WdtTimeout::default());

    loop {}
}

test_suite! {
    test_wdt_timeout,
}
