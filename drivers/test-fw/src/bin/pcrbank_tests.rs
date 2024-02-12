/*++

Licensed under the Apache-2.0 license.

File Name:

    pcrbank_tests.rs

Abstract:

    File contains test cases for PCR bank API

--*/

#![no_std]
#![no_main]

use caliptra_drivers::{PcrBank, PcrId};
use caliptra_registers::pv::PvReg;

use caliptra_test_harness::test_suite;

const PCR_IDS: [PcrId; 32] = [
    PcrId::PcrId0,
    PcrId::PcrId1,
    PcrId::PcrId2,
    PcrId::PcrId3,
    PcrId::PcrId4,
    PcrId::PcrId5,
    PcrId::PcrId6,
    PcrId::PcrId7,
    PcrId::PcrId8,
    PcrId::PcrId9,
    PcrId::PcrId10,
    PcrId::PcrId11,
    PcrId::PcrId12,
    PcrId::PcrId13,
    PcrId::PcrId14,
    PcrId::PcrId15,
    PcrId::PcrId16,
    PcrId::PcrId17,
    PcrId::PcrId18,
    PcrId::PcrId19,
    PcrId::PcrId20,
    PcrId::PcrId21,
    PcrId::PcrId22,
    PcrId::PcrId23,
    PcrId::PcrId24,
    PcrId::PcrId25,
    PcrId::PcrId26,
    PcrId::PcrId27,
    PcrId::PcrId28,
    PcrId::PcrId29,
    PcrId::PcrId30,
    PcrId::PcrId31,
];

fn test_read_write() {
    let mut pv = unsafe {
        PvReg::new()
    };

    let hash = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc];

    pv.regs_mut().pcr_entry().at(PcrId::PcrId0.into()).write(&hash);
    let read_hash = pv.regs().pcr_entry().at(PcrId::PcrId0.into()).read();
    assert_eq!(read_hash, hash)
}

fn test_lock_and_erase_pcrs() {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.erase_pcr(pcr_id).is_ok());

        // Set lock.
        assert!(!pcr_bank.pcr_lock(pcr_id));
        pcr_bank.set_pcr_lock(pcr_id);
        assert!(pcr_bank.pcr_lock(pcr_id));

        // Test erasing pcr. This should fail.
        assert!(pcr_bank.erase_pcr(pcr_id).is_err());
    }
}

fn test_erase_all_pcrs() {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    pcr_bank.erase_all_pcrs();
}

fn test_write_protection_stickiness() {
    let mut pcr_bank = unsafe { PcrBank::new(PvReg::new()) };
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.pcr_lock(pcr_id));
        pcr_bank.clear_pcr_lock(pcr_id);
        assert!(pcr_bank.pcr_lock(pcr_id));
    }
}

// Maintain the order of the tests.
test_suite! {
    test_read_write,
    test_lock_and_erase_pcrs,
    test_erase_all_pcrs,
    test_write_protection_stickiness,
}
