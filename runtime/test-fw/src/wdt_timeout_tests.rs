/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_drivers::WdtTimeout;
use caliptra_drivers::{start_wdt, stop_wdt};
use caliptra_runtime::Drivers;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_wdt_timeout() {
    let mut drivers = unsafe { Drivers::new_from_registers().unwrap() };

    start_wdt(&mut drivers.soc_ifc, WdtTimeout::default());

    stop_wdt(&mut drivers.soc_ifc);

    start_wdt(&mut drivers.soc_ifc, WdtTimeout::default());
    loop {}
}

test_suite! {
    test_wdt_timeout,
}
