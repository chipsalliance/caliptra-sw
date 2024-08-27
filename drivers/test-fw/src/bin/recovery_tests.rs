/*++

Licensed under the Apache-2.0 license.

File Name:

recovery_tests.rs

Abstract:

File contains test cases for the recovery register interface

--*/

#![no_std]
#![no_main]

use arrayvec::ArrayVec;
use caliptra_drivers::{CmsType, Recovery, RecoveryCmsReq};
use caliptra_error::CaliptraError;
use caliptra_registers::recovery::RecoveryReg;
use caliptra_test_harness::test_suite;

fn test_recovery() {
    // Synchronize with test
    let test_image = [0xab; 512];

    let recovery_reg = unsafe { RecoveryReg::new() };
    let mut recovery = Recovery::new(recovery_reg);

    let recovery_req = RecoveryCmsReq(0);
    let ret = recovery.request_cms(recovery_req).unwrap();

    assert_eq!(ret.cms_type, CmsType::CodeSpace);
    assert_eq!(ret.size, test_image.len().try_into().unwrap());

    let image: ArrayVec<u8, 512> = {
        let mut image = ArrayVec::new();
        recovery.into_iter().for_each(|dw| {
            let bytes = dw.to_le_bytes();
            image.try_extend_from_slice(&bytes).unwrap()
        });
        image
    };

    assert_eq!(test_image, image.as_slice());
}

fn test_invalid_image() {
    let recovery_reg = unsafe { RecoveryReg::new() };
    let mut recovery = Recovery::new(recovery_reg);

    const UNUSED_CMS: u8 = 240;

    let recovery_req = RecoveryCmsReq(UNUSED_CMS);
    let result = recovery.request_cms(recovery_req);
    assert_eq!(result, Err(CaliptraError::DRIVER_RECOVERY_INVALID_CMS));
}

test_suite! {
    test_recovery,
    test_invalid_image,
}
