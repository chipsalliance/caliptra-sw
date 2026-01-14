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

/// DCCM (Data Closely Coupled Memory)
///
/// Layout
///
/// | Partition       | Field        | Start       | End         | Size                 |
/// |-----------------|--------------|-------------|-------------|----------------------|
/// | DCCM            |              | 0x5000_0000 | 0x5004_0000 | 0x4_0000             |
/// | Stack           |              | 0x5000_0000 | 0x5002_3800 | 0x2_3800             |
/// |                 | FW Stack     | 0x5000_0000 | 0x5002_3000 | 0x2_3000             |
/// |                 | ROM Stack    | 0x5000_0000 | 0x5001_8000 | 0x1_8000             |
/// |                 | EStack       | 0x5002_3000 | 0x5002_3400 | 0x400                |
/// |                 | NStack       | 0x5002_3400 | 0x5002_3800 | 0x400                |
/// | Extra memory    |              | 0x5002_3800 | Extra end   | Extra memory size    |
/// | Persistent Data |              | Extra end   | 0x5003_fc00 | Persistent data size |
/// | ROM Data        |              | 0x5003_fc00 | 0x5004_0000 | 0x400                |
/// |                 | Reserved     | 0x5003_fc00 | 0x5003_ffe4 | 0x3e4                |
/// |                 | CFI State    | 0x5003_ffe4 | 0x5003_fffc | 0x18                 |
/// |                 | Boot Status  | 0x5003_fffc | 0x5004_0000 | 0x4                  |
pub const DCCM_ORG: u32 = 0x50000000;

/// Stack is placed at the beginning of DCCM so a stack overflow will cause a hardware fault
pub const STACK_ORG: u32 = DCCM_ORG;
pub const ROM_STACK_ORG: u32 = STACK_ORG;

/// Exception stack
pub const ESTACK_ORG: u32 = STACK_ORG + STACK_SIZE;
pub const ROM_ESTACK_ORG: u32 = ESTACK_ORG;

/// NMI stack
pub const NSTACK_ORG: u32 = ESTACK_ORG + ESTACK_SIZE;
pub const ROM_NSTACK_ORG: u32 = NSTACK_ORG;

/// Extra memory reserved for stack and/or persistent data growth
pub const EXTRA_MEMORY_ORG: u32 = NSTACK_ORG + NSTACK_SIZE;

/// Persistent data shared between boot stages and stored across warm and update resets
pub const PERSISTENT_DATA_ORG: u32 = ROM_DATA_ORG - size_of::<PersistentData>() as u32;

pub const ROM_DATA_ORG: u32 = DCCM_ORG + DCCM_SIZE - ROM_DATA_SIZE;
pub const CFI_STATE_ORG: u32 = ROM_DATA_ORG + 0x3E4; // size = 6 words
pub const BOOT_STATUS_ORG: u32 = ROM_DATA_ORG + 0x3FC;
pub const LAST_REGION_END: u32 = ROM_DATA_ORG + ROM_DATA_SIZE;

//
// Memory Sizes In Bytes
//

pub const ROM_RELAXATION_PADDING: u32 = 4 * 1024;
pub const ROM_SIZE: u32 = 96 * 1024;
pub const MAX_MBOX_SIZE: u32 = 256 * 1024; // Actual size depens on hw revision and subsystem being present
pub const MBOX_SIZE_PASSIVE_MODE: u32 = 16 * 1024;
pub const ICCM_SIZE: u32 = 256 * 1024;
pub const DCCM_SIZE: u32 = 256 * 1024;
pub const ROM_DATA_SIZE: u32 = 1024;
pub const ROM_DATA_RESERVED_SIZE: u32 = 996;
pub const STACK_SIZE: u32 = 140 * 1024;
pub const ROM_STACK_SIZE: u32 = 96 * 1024;
pub const ESTACK_SIZE: u32 = 1024;
pub const ROM_ESTACK_SIZE: u32 = 1024;
pub const NSTACK_SIZE: u32 = 1024;
pub const ROM_NSTACK_SIZE: u32 = 1024;
pub const EXTRA_MEMORY_SIZE: u32 = DCCM_SIZE
    - NSTACK_SIZE
    - ESTACK_SIZE
    - STACK_SIZE
    - ROM_DATA_SIZE
    - size_of::<PersistentData>() as u32;

pub const ICCM_RANGE: core::ops::Range<u32> = core::ops::Range {
    start: ICCM_ORG,
    end: ICCM_ORG + ICCM_SIZE,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_stacks_start() {
    assert_eq!(DCCM_ORG, STACK_ORG);
    assert_eq!(DCCM_ORG, ROM_STACK_ORG);
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
fn mem_layout_test_nstack() {
    assert_eq!((EXTRA_MEMORY_ORG - NSTACK_ORG), NSTACK_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_extra_memory() {
    assert_eq!((PERSISTENT_DATA_ORG - EXTRA_MEMORY_ORG), EXTRA_MEMORY_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_persistent_data() {
    assert_eq!(
        (ROM_DATA_ORG - PERSISTENT_DATA_ORG),
        size_of::<PersistentData>() as u32
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_rom_data() {
    assert_eq!((DCCM_ORG + DCCM_SIZE - ROM_DATA_ORG), ROM_DATA_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn dccm_overflow() {
    assert!(DCCM_ORG + DCCM_SIZE >= LAST_REGION_END);
}
