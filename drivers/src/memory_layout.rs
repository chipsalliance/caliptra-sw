/*++
Licensed under the Apache-2.0 license.

File Name:

    memory_layout.rs

Abstract:

    The file contains the layout of memory. The constants defined
    in this file define the memory layout.

--*/

#[cfg(test)]
use crate::FirmwareHandoffTable;

#[cfg(test)]
use caliptra_image_types::ImageManifest;

//
// Memory Addresses
//
pub const ROM_ORG: u32 = 0x00000000;
pub const MBOX_ORG: u32 = 0x30000000;
pub const ICCM_ORG: u32 = 0x40000000;
pub const DCCM_ORG: u32 = 0x50000000;
pub const CFI_VAL_ORG: u32 = 0x500003E4;
pub const CFI_MASK_ORG: u32 = 0x500003E8;
pub const CFI_XO_S0_ORG: u32 = 0x500003EC;
pub const CFI_XO_S1_ORG: u32 = 0x500003F0;
pub const CFI_XO_S2_ORG: u32 = 0x500003F4;
pub const CFI_XO_S3_ORG: u32 = 0x500003F8;
pub const BOOT_STATUS_ORG: u32 = 0x500003FC;
pub const MAN1_ORG: u32 = 0x50000400;
pub const MAN2_ORG: u32 = 0x50001C00;
pub const FHT_ORG: u32 = 0x50003400;
pub const LDEVID_TBS_ORG: u32 = 0x50003C00;
pub const FMCALIAS_TBS_ORG: u32 = 0x50004000;
pub const RTALIAS_TBS_ORG: u32 = 0x50004400;
pub const PCR_LOG_ORG: u32 = 0x50004800;
pub const MEASUREMENT_LOG_ORG: u32 = 0x50004C00;
pub const FUSE_LOG_ORG: u32 = 0x50005000;
pub const DPE_ORG: u32 = 0x50005400;
pub const DATA_ORG: u32 = 0x50006400;
pub const STACK_ORG: u32 = 0x5001A000;
pub const ESTACK_ORG: u32 = 0x5001F800;
pub const NSTACK_ORG: u32 = 0x5001FC00;

//
// Memory Sizes In Bytes
//
pub const ROM_RELAXATION_PADDING: u32 = 4 * 1024;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const MBOX_SIZE: u32 = 128 * 1024;
pub const ICCM_SIZE: u32 = 128 * 1024;
pub const DCCM_SIZE: u32 = 128 * 1024;
pub const MAN1_SIZE: u32 = 6 * 1024;
pub const MAN2_SIZE: u32 = 6 * 1024;
pub const FHT_SIZE: u32 = 2 * 1024;
pub const LDEVID_TBS_SIZE: u32 = 1024;
pub const FMCALIAS_TBS_SIZE: u32 = 1024;
pub const RTALIAS_TBS_SIZE: u32 = 1024;
pub const PCR_LOG_SIZE: u32 = 1024;
pub const MEASUREMENT_LOG_SIZE: u32 = 1024;
pub const FUSE_LOG_SIZE: u32 = 1024;
pub const DPE_SIZE: u32 = 4 * 1024;
pub const DATA_SIZE: u32 = 79 * 1024;
pub const STACK_SIZE: u32 = 22 * 1024;
pub const ESTACK_SIZE: u32 = 1024;
pub const NSTACK_SIZE: u32 = 1024;

pub const ICCM_RANGE: core::ops::Range<u32> = core::ops::Range {
    start: ICCM_ORG,
    end: ICCM_ORG + ICCM_SIZE,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_manifest() {
    assert!(MAN1_SIZE as usize >= core::mem::size_of::<ImageManifest>());
    assert!(MAN2_SIZE as usize >= core::mem::size_of::<ImageManifest>());
    assert_eq!(MAN1_SIZE, MAN2_SIZE);
    assert_eq!((MAN2_ORG - MAN1_ORG), MAN1_SIZE);
    assert_eq!((FHT_ORG - MAN2_ORG), MAN2_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_fht() {
    assert!(FHT_SIZE as usize >= core::mem::size_of::<FirmwareHandoffTable>());
    assert_eq!((LDEVID_TBS_ORG - FHT_ORG), FHT_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_ldevid() {
    assert_eq!((FMCALIAS_TBS_ORG - LDEVID_TBS_ORG), LDEVID_TBS_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_fmcalias() {
    assert_eq!((RTALIAS_TBS_ORG - FMCALIAS_TBS_ORG), FMCALIAS_TBS_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_rtalias() {
    assert_eq!((PCR_LOG_ORG - RTALIAS_TBS_ORG), RTALIAS_TBS_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_pcr_log() {
    assert_eq!((MEASUREMENT_LOG_ORG - PCR_LOG_ORG), PCR_LOG_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_measurement_log() {
    assert_eq!((FUSE_LOG_ORG - MEASUREMENT_LOG_ORG), MEASUREMENT_LOG_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_fuselog() {
    assert_eq!((DPE_ORG - FUSE_LOG_ORG), FUSE_LOG_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_dpe() {
    assert_eq!((DATA_ORG - DPE_ORG), DPE_SIZE);
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
