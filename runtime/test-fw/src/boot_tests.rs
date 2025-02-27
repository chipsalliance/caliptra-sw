/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_tests.rs

Abstract:

    File contains test cases for booting runtime firmware

--*/

#![no_std]
#![no_main]

use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::{runtime_handlers, test_suite};

fn test_boot() {}

test_suite! {
    test_boot,
}
