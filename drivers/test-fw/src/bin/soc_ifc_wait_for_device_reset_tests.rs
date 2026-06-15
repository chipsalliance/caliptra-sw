// Licensed under the Apache-2.0 license

#![no_std]
#![no_main]

use caliptra_drivers::SocIfc;
use caliptra_registers::soc_ifc::SocIfcReg;
use caliptra_test_harness::test_suite;

fn test_wait_for_device_reset_before_fatal_error() {
    let soc_ifc = SocIfc::new(unsafe { SocIfcReg::new() });
    assert!(soc_ifc.wait_for_device_reset_before_fatal_error());
}

test_suite! {
    test_wait_for_device_reset_before_fatal_error,
}
