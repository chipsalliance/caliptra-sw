/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_common::handle_fatal_error;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_runtime::Drivers;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_boot() {
    let mut drivers = unsafe {
        Drivers::new_from_registers().unwrap_or_else(|e| {
            handle_fatal_error(e.into());
        })
    };
    drivers.soc_ifc.assert_ready_for_runtime();
}

test_suite! {
    test_boot,
}
