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

#[cfg(test)]
use crate::MlDsa87PubKey;

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
pub const MAN1_ORG: u32 = 0x50000400;
pub const MAN2_ORG: u32 = MAN1_ORG + MAN1_SIZE;
pub const FHT_ORG: u32 = MAN2_ORG + MAN2_SIZE;
pub const IDEVID_MLDSA_PUB_KEY_ORG: u32 = FHT_ORG + FHT_SIZE;
pub const LDEVID_TBS_ORG: u32 = IDEVID_MLDSA_PUB_KEY_ORG + IDEVID_MLDSA_PUB_KEY_MAX_SIZE;
pub const FMCALIAS_TBS_ORG: u32 = LDEVID_TBS_ORG + LDEVID_TBS_SIZE;
pub const RTALIAS_TBS_ORG: u32 = FMCALIAS_TBS_ORG + FMCALIAS_TBS_SIZE;
pub const PCR_LOG_ORG: u32 = RTALIAS_TBS_ORG + RTALIAS_TBS_SIZE;
pub const MEASUREMENT_LOG_ORG: u32 = PCR_LOG_ORG + PCR_LOG_SIZE;
pub const FUSE_LOG_ORG: u32 = MEASUREMENT_LOG_ORG + MEASUREMENT_LOG_SIZE;
pub const DPE_ORG: u32 = FUSE_LOG_ORG + FUSE_LOG_SIZE;
pub const PCR_RESET_COUNTER_ORG: u32 = DPE_ORG + DPE_SIZE;
pub const AUTH_MAN_IMAGE_METADATA_LIST_ORG: u32 = PCR_RESET_COUNTER_ORG + PCR_RESET_COUNTER_SIZE;
pub const DATA_ORG: u32 = AUTH_MAN_IMAGE_METADATA_LIST_ORG + AUTH_MAN_IMAGE_METADATA_LIST_MAX_SIZE;

pub const STACK_ORG: u32 = DATA_ORG + DATA_SIZE;
pub const ROM_STACK_ORG: u32 = STACK_ORG + (STACK_SIZE - ROM_STACK_SIZE);

pub const ESTACK_ORG: u32 = ROM_STACK_ORG + ROM_STACK_SIZE;
pub const ROM_ESTACK_ORG: u32 = ESTACK_ORG;

pub const NSTACK_ORG: u32 = ROM_ESTACK_ORG + ROM_ESTACK_SIZE;
pub const ROM_NSTACK_ORG: u32 = NSTACK_ORG;

//
// Memory Sizes In Bytes
//
pub const ROM_RELAXATION_PADDING: u32 = 4 * 1024;
pub const ROM_SIZE: u32 = 48 * 1024;
pub const MBOX_SIZE: u32 = 128 * 1024;
pub const ICCM_SIZE: u32 = 128 * 1024;
pub const DCCM_SIZE: u32 = 128 * 1024;
pub const ROM_DATA_SIZE: u32 = 996;
pub const MAN1_SIZE: u32 = 8 * 1024;
pub const MAN2_SIZE: u32 = 8 * 1024;
pub const FHT_SIZE: u32 = 2 * 1024;
pub const IDEVID_MLDSA_PUB_KEY_MAX_SIZE: u32 = 3 * 1024;
pub const LDEVID_TBS_SIZE: u32 = 1024;
pub const FMCALIAS_TBS_SIZE: u32 = 1024;
pub const RTALIAS_TBS_SIZE: u32 = 1024;
pub const PCR_LOG_SIZE: u32 = 1024;
pub const MEASUREMENT_LOG_SIZE: u32 = 1024;
pub const FUSE_LOG_SIZE: u32 = 1024;
pub const DPE_SIZE: u32 = 5 * 1024;
pub const PCR_RESET_COUNTER_SIZE: u32 = 1024;
pub const AUTH_MAN_IMAGE_METADATA_LIST_MAX_SIZE: u32 = 1024;
pub const DATA_SIZE: u32 = 69 * 1024;
pub const STACK_SIZE: u32 = 22 * 1024;
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
    assert_eq!((IDEVID_MLDSA_PUB_KEY_ORG - FHT_ORG), FHT_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_idevid_mldsa_pub_key() {
    assert!(IDEVID_MLDSA_PUB_KEY_MAX_SIZE as usize >= core::mem::size_of::<MlDsa87PubKey>());
    assert_eq!(
        (LDEVID_TBS_ORG - IDEVID_MLDSA_PUB_KEY_ORG),
        IDEVID_MLDSA_PUB_KEY_MAX_SIZE
    );
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
    assert_eq!((PCR_RESET_COUNTER_ORG - DPE_ORG), DPE_SIZE);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn mem_layout_test_pcr_reset_counter() {
    assert_eq!(
        (AUTH_MAN_IMAGE_METADATA_LIST_ORG - PCR_RESET_COUNTER_ORG),
        PCR_RESET_COUNTER_SIZE
    );
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
