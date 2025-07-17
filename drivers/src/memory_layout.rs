/*++
Licensed under the Apache-2.0 license.

File Name:

    memory_layout.rs

Abstract:

    The file contains the layout of memory. The constants defined
    in this file define the memory layout.

--*/

use core::mem::size_of;

use crate::PersistentData;

//
// Memory Addresses
//
pub const ROM_ORG: u32 = 0x00000000;
pub const MBOX_ORG: u32 = 0x30040000;
pub const ICCM_ORG: u32 = 0x40000000;
pub const DCCM_ORG: u32 = 0x50000000;
pub const ROM_DATA_ORG: u32 = 0x50000000;
pub const CFI_STATE_ORG: u32 = 0x500003E4; // size = 6 words
pub const BOOT_STATUS_ORG: u32 = 0x500003FC;
pub const PERSISTENT_DATA_ORG: u32 = 0x50000400;

pub const DATA_ORG: u32 = PERSISTENT_DATA_ORG + size_of::<PersistentData>() as u32;

pub const STACK_ORG: u32 = DATA_ORG + DATA_SIZE;
pub const ROM_STACK_ORG: u32 = STACK_ORG + (STACK_SIZE - ROM_STACK_SIZE);

pub const ESTACK_ORG: u32 = ROM_STACK_ORG + ROM_STACK_SIZE;
pub const ROM_ESTACK_ORG: u32 = ESTACK_ORG;

pub const NSTACK_ORG: u32 = ROM_ESTACK_ORG + ROM_ESTACK_SIZE;
pub const ROM_NSTACK_ORG: u32 = NSTACK_ORG;

pub const LAST_REGION_END: u32 = NSTACK_ORG + NSTACK_SIZE;

//
// Memory Sizes In Bytes
//

pub const ROM_RELAXATION_PADDING: u32 = 4 * 1024;
pub const ROM_SIZE: u32 = 96 * 1024;
pub const MBOX_SIZE: u32 = 256 * 1024; // Do not use in code as it depends on revision
pub const ICCM_SIZE: u32 = 256 * 1024;
pub const DCCM_SIZE: u32 = 256 * 1024;
pub const ROM_DATA_SIZE: u32 = 996;
pub const STACK_SIZE: u32 = 104 * 1024;
pub const ROM_STACK_SIZE: u32 = 62 * 1024;
pub const ESTACK_SIZE: u32 = 1024;
pub const ROM_ESTACK_SIZE: u32 = 1024;
pub const NSTACK_SIZE: u32 = 1024;
pub const ROM_NSTACK_SIZE: u32 = 1024;
// This is mostly used for relaxation ptrs and is basically padding otherwise.
pub const DATA_SIZE: u32 = DCCM_SIZE
    - NSTACK_SIZE
    - ROM_ESTACK_SIZE
    - STACK_SIZE
    - size_of::<PersistentData>() as u32
    - (PERSISTENT_DATA_ORG - DCCM_ORG);

pub const ICCM_RANGE: core::ops::Range<u32> = core::ops::Range {
    start: ICCM_ORG,
    end: ICCM_ORG + ICCM_SIZE,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_persistent_data() {
    assert_eq!(
        (DATA_ORG - PERSISTENT_DATA_ORG),
        size_of::<PersistentData>() as u32
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_data() {
    assert_eq!((STACK_ORG - DATA_ORG), DATA_SIZE);
    // we must leave room for 0x800 bytes for the relaxation pointers
    assert!(DATA_SIZE >= 2 * 1024);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_stack() {
    assert_eq!((ESTACK_ORG - STACK_ORG), STACK_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_estack() {
    assert_eq!((NSTACK_ORG - ESTACK_ORG), ESTACK_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn dccm_overflow() {
    assert!(DCCM_ORG + DCCM_SIZE >= LAST_REGION_END);
}
