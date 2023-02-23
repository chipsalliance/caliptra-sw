/*++

Licensed under the Apache-2.0 license.

File Name:

    pcrbank_tests.rs

Abstract:

    File contains test cases for PCR bank API

--*/

#![no_std]
#![no_main]

use caliptra_lib::{Array4x12, PcrBank, PcrId};

mod harness;

const PCR_IDS: [PcrId; 8] = [
    PcrId::PcrId0,
    PcrId::PcrId1,
    PcrId::PcrId2,
    PcrId::PcrId3,
    PcrId::PcrId4,
    PcrId::PcrId5,
    PcrId::PcrId6,
    PcrId::PcrId7,
];

const PCR: [u8; 48] = [
    0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];

const EMPTY_PCR: [u8; 48] = [0; 48];

fn test_read_write() {
    let pcr_bank = PcrBank::default();
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.write_pcr(pcr_id, &Array4x12::from(PCR)).is_ok());
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(PCR));
    }
}

fn test_erase_pcr() {
    let mut pcr_bank = PcrBank::default();
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.write_pcr(pcr_id, &Array4x12::from(PCR)).is_ok());
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(PCR));
        assert!(pcr_bank.erase_pcr(pcr_id).is_ok());
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(EMPTY_PCR));
    }
}

fn test_erase_all_pcrs() {
    let mut pcr_bank = PcrBank::default();
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.write_pcr(pcr_id, &Array4x12::from(PCR)).is_ok());
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(PCR));
    }

    pcr_bank.erase_all_pcrs();

    for pcr_id in PCR_IDS {
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(EMPTY_PCR));
    }
}

fn test_write_lock() {
    let mut pcr_bank = PcrBank::default();

    for pcr_id in PCR_IDS {
        assert!(!pcr_bank.pcr_write_lock(pcr_id));

        assert!(pcr_bank.write_pcr(pcr_id, &Array4x12::from(PCR)).is_ok());

        pcr_bank.set_pcr_write_lock(pcr_id);
        assert!(pcr_bank.pcr_write_lock(pcr_id));

        // Try writing to the pcr. This should fail.
        assert!(pcr_bank.write_pcr(pcr_id, &Array4x12::from(PCR)).is_err());
    }
}

fn test_try_erase_all_write_protected_pcrs() {
    let mut pcr_bank = PcrBank::default();
    for pcr_id in PCR_IDS {
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(PCR));
        assert!(pcr_bank.pcr_write_lock(pcr_id));
    }
    pcr_bank.erase_all_pcrs(); // This should be a no-op.
    for pcr_id in PCR_IDS {
        assert_eq!(pcr_bank.read_pcr(pcr_id), Array4x12::from(PCR));
    }
}

fn test_write_protection_stickiness() {
    let mut pcr_bank = PcrBank::default();
    for pcr_id in PCR_IDS {
        assert!(pcr_bank.pcr_write_lock(pcr_id));
        pcr_bank.clear_pcr_write_lock(pcr_id);
        assert!(pcr_bank.pcr_write_lock(pcr_id));
    }
}

// Maintain the order of the tests.
test_suite! {
    test_read_write,
    test_erase_pcr,
    test_erase_all_pcrs,
    test_write_lock,
    test_try_erase_all_write_protected_pcrs,
    test_write_protection_stickiness,
}
