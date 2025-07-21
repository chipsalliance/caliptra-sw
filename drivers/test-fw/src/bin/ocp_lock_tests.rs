/*++

Licensed under the Apache-2.0 license.

File Name:

    ocp_lock.rs

Abstract:

    File contains test cases for OCP LOCK.

--*/


#![no_std]
#![no_main]

use caliptra_drivers::SocIfc;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::test_suite;

fn test_hw_supports_ocp_lock() {
    let soc_ifc = unsafe { SocIfcReg::new() };
     assert_eq!(SocIfc::new(soc_ifc).ocp_lock_enabled(), true);
}

test_suite! {
    test_hw_supports_ocp_lock,
}
