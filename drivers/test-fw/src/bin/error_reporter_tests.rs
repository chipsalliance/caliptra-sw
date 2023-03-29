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
    report_fw_error_fatal, report_fw_error_non_fatal, report_hw_error_fatal,
    report_hw_error_non_fatal,
};
use caliptra_registers::soc_ifc;

mod harness;

fn test_report_fw_error() {
    let v: u32 = 0xdead0;
    report_fw_error_non_fatal(0xdead0);

    assert_eq!(v, retrieve_fw_error_non_fatal());
}

fn retrieve_fw_error_non_fatal() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_fw_error_non_fatal().read()
}

fn test_report_fw_error_fatal() {
    let v: u32 = 0xdead1;

    report_fw_error_fatal(v);

    assert_eq!(v, retrieve_fw_error_fatal());
}

fn retrieve_fw_error_fatal() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_fw_error_fatal().read()
}

fn retrieve_hw_error_non_fatal() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_hw_error_non_fatal().read()
}

fn test_report_hw_error() {
    let v: u32 = 0xdead2;
    report_hw_error_non_fatal(0xdead2);
    assert_eq!(v, retrieve_hw_error_non_fatal());
}

fn test_report_hw_error_fatal() {
    let v: u32 = 0xdead3;
    report_hw_error_fatal(v);
    assert_eq!(v, retrieve_hw_error_fatal());
}

fn retrieve_hw_error_fatal() -> u32 {
    let soc_ifc = soc_ifc::RegisterBlock::soc_ifc_reg();
    soc_ifc.cptra_hw_error_fatal().read()
}

test_suite! {
    test_report_fw_error,
    test_report_fw_error_fatal,
    test_report_hw_error,
    test_report_hw_error_fatal,
}
