// Licensed under the Apache-2.0 license

//! A very simple program that extends to a PCR and then computes a hash.

#![no_main]
#![no_std]

use caliptra_cfi_lib::{CfiCounter, CfiPanicInfo};
use caliptra_drivers::{Array4x12, CaliptraError, PcrBank, PcrId, Sha384};
use caliptra_registers::{pv::PvReg, sha512::Sha512Reg};
#[allow(unused)]
use caliptra_test_harness::println;

#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    caliptra_drivers::ExitCtrl::exit(1)
}

#[no_mangle]
extern "C" fn cfi_panic_handler(info: CfiPanicInfo) -> ! {
    let caliptra_error: CaliptraError = info.into();
    let error_code = caliptra_error.0.get();

    println!("[test_pcr_extend] CFI Panic code=0x{:08X}", error_code);
    caliptra_drivers::report_fw_error_fatal(error_code);
    caliptra_drivers::ExitCtrl::exit(u32::MAX)
}

#[no_mangle]
extern "C" fn main() {
    // Init CFI
    CfiCounter::reset(&mut || Ok([0xDEADBEEFu32; 12]));

    let mut sha384 = unsafe { Sha384::new(Sha512Reg::new()) };
    let pcr_bank = unsafe { PcrBank::new(PvReg::new()) };

    pcr_bank
        .extend_pcr(PcrId::PcrId1, &mut sha384, &[0_u8; 4])
        .unwrap();

    let pcr1 = pcr_bank.read_pcr(PcrId::PcrId1);

    let expected_pcr1 = [
        0x1a, 0xe0, 0x93, 0xc2, 0xc1, 0x3b, 0xbe, 0xea, 0x8a, 0xbe, 0x39, 0xe0, 0xfc, 0x3a, 0x03,
        0x40, 0xbd, 0xaf, 0x0a, 0x0b, 0x55, 0xf0, 0x93, 0x61, 0x66, 0xfd, 0x32, 0x5b, 0x2d, 0x4c,
        0xbf, 0x7a, 0x95, 0x25, 0xf9, 0x3a, 0x92, 0x60, 0x38, 0xf7, 0x0a, 0x1a, 0xc5, 0x7d, 0x32,
        0x86, 0xff, 0xab,
    ];

    assert_eq!(pcr1, Array4x12::from(expected_pcr1));

    let digest = sha384.digest(&expected_pcr1).unwrap();

    let expected_digest = [
        0x5f, 0xeb, 0xea, 0xe8, 0x58, 0x75, 0x73, 0x40, 0x29, 0x58, 0xa9, 0x24, 0xba, 0x75, 0xc7,
        0x50, 0x39, 0x73, 0xee, 0x94, 0x76, 0xfb, 0xac, 0xb5, 0xba, 0xfe, 0x69, 0x53, 0xbf, 0xde,
        0x06, 0xa2, 0xdf, 0x89, 0x5e, 0xff, 0xd8, 0x13, 0xc5, 0x38, 0x9a, 0x4b, 0xed, 0x4b, 0x37,
        0x11, 0x03, 0xc1,
    ];

    assert_eq!(digest, Array4x12::from(expected_digest));

    // Assert PCR1 is still the expected value.
    let pcr1 = pcr_bank.read_pcr(PcrId::PcrId1);

    assert_eq!(pcr1, Array4x12::from(expected_pcr1));
}
