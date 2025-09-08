/*++

Licensed under the Apache-2.0 license.

File Name:

    error_reporter_tests.rs

Abstract:

    File contains test cases for HMAC-384 API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{
    clear_fw_error_non_fatal, get_fw_error_non_fatal, report_fw_error_fatal,
    report_fw_error_non_fatal, PersistentDataAccessor,
};
use caliptra_registers::soc_ifc::SocIfcReg;

use caliptra_test_harness::test_suite;

fn test_report_fw_error() {
    let v: u32 = 0xdead0;
    report_fw_error_non_fatal(v);

    assert_eq!(v, get_fw_error_non_fatal());
}

fn test_clear_fw_error_non_fatal() {
    let err1: u32 = 0xdead1;
    let err2: u32 = 0xdead2;

    let mut persistent_data_accessor = unsafe { PersistentDataAccessor::new() };
    let persistent_data = persistent_data_accessor.get_mut();

    report_fw_error_non_fatal(err1);
    assert_eq!(err1, get_fw_error_non_fatal());

    // Ensure clear function zeros the fw_non_fatal_error and stores it in persistent data correctly
    clear_fw_error_non_fatal(persistent_data);
    assert_eq!(0, get_fw_error_non_fatal());
    assert_eq!(err1, persistent_data.cleared_non_fatal_fw_error);

    // Write a new error
    report_fw_error_non_fatal(err2);
    assert_eq!(err2, get_fw_error_non_fatal());

    clear_fw_error_non_fatal(persistent_data);
    assert_eq!(0, get_fw_error_non_fatal());
    assert_eq!(err2, persistent_data.cleared_non_fatal_fw_error);

    // Repeatedly clearing should not overwrite the stored previous error when no error is present
    clear_fw_error_non_fatal(persistent_data);
    clear_fw_error_non_fatal(persistent_data);
    assert_eq!(0, get_fw_error_non_fatal());
    assert_eq!(err2, persistent_data.cleared_non_fatal_fw_error);
}

fn test_report_fw_error_fatal() {
    let v: u32 = 0xdead1;

    report_fw_error_fatal(v);

    assert_eq!(v, retrieve_fw_error_fatal());
}

fn retrieve_fw_error_fatal() -> u32 {
    let soc_ifc = unsafe { SocIfcReg::new() };
    soc_ifc.regs().cptra_fw_error_fatal().read()
}

test_suite! {
    test_report_fw_error,
    test_clear_fw_error_non_fatal,
    test_report_fw_error_fatal,
}
