/*++
Licensed under the Apache-2.0 license.

File Name:

    memory_layout.rs

Abstract:

    The file contains the layout of memory. The constants defined
    in this file define the memory layout.

--*/

//
// Memory Addresses
//
pub const ROM_ORG: u32 = 0x00000000;
pub const MBOX_ORG: u32 = 0x30000000;
pub const ICCM_ORG: u32 = 0x40000000;
pub const DCCM_ORG: u32 = 0x50000000;
pub const ROM_DATA_ORG: u32 = 0x50000000;
pub const CFI_STATE_ORG: u32 = 0x500003E4; // size = 6 words
pub const BOOT_STATUS_ORG: u32 = 0x500003FC;
pub const PERSISTENT_DATA_ORG: u32 = 0x50000400;

pub const DATA_ORG: u32 = 0x5000D800;

pub const STACK_ORG: u32 = 0x5000f800;
pub const ROM_STACK_ORG: u32 = 0x5001C000;

pub const ESTACK_ORG: u32 = 0x5001F800;
pub const ROM_ESTACK_ORG: u32 = 0x5001F800;

pub const NSTACK_ORG: u32 = 0x5001FC00;
pub const ROM_NSTACK_ORG: u32 = 0x5001FC00;

//
// Memory Sizes In Bytes
//

// Reserves a large chunk of DCCM for the PersistentData struct.
//
// The size was calculated by leaving a portion of the Data section
// reserved for future use and then allocating the rest of the DCCM.
//
// The `DATA_SIZE` variable reflects the leftover space.
pub const PERSISTENT_DATA_SIZE: u32 = 53 * 1024;

pub const ROM_RELAXATION_PADDING: u32 = 4 * 1024;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const MBOX_SIZE: u32 = 128 * 1024;
pub const ICCM_SIZE: u32 = 128 * 1024;
pub const DCCM_SIZE: u32 = 128 * 1024;
pub const ROM_DATA_SIZE: u32 = 996;
pub const DATA_SIZE: u32 = 8 * 1024;
pub const STACK_SIZE: u32 = 64 * 1024;
pub const ROM_STACK_SIZE: u32 = 14 * 1024;
pub const ESTACK_SIZE: u32 = 1024;
pub const ROM_ESTACK_SIZE: u32 = 1024;
pub const NSTACK_SIZE: u32 = 1024;
pub const ROM_NSTACK_SIZE: u32 = 1024;

pub const ICCM_RANGE: core::ops::Range<u32> = core::ops::Range {
    start: ICCM_ORG,
    end: ICCM_ORG + ICCM_SIZE,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_persistent_data() {
    assert_eq!((DATA_ORG - PERSISTENT_DATA_ORG), PERSISTENT_DATA_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_data() {
    assert_eq!((STACK_ORG - DATA_ORG), DATA_SIZE);
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
