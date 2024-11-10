// Licensed under the Apache-2.0 license

use core::{marker::PhantomData, mem::size_of, ptr::addr_of};

#[cfg(feature = "runtime")]
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection,
    AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
};
use caliptra_image_types::ImageManifest;
#[cfg(feature = "runtime")]
use dpe::{DpeInstance, U8Bool, MAX_HANDLES};
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

use crate::{
    fuse_log::FuseLogEntry,
    memory_layout,
    pcr_log::{MeasurementLogEntry, PcrLogEntry},
    FirmwareHandoffTable,
};

#[cfg(feature = "runtime")]
use crate::pcr_reset::PcrResetCounter;

pub const PCR_LOG_MAX_COUNT: usize = 17;
pub const FUSE_LOG_MAX_COUNT: usize = 62;
pub const MEASUREMENT_MAX_COUNT: usize = 8;

#[cfg(feature = "runtime")]
const DPE_DCCM_STORAGE: usize = size_of::<DpeInstance>()
    + size_of::<u32>() * MAX_HANDLES
    + size_of::<U8Bool>() * MAX_HANDLES
    + size_of::<U8Bool>();

#[cfg(feature = "runtime")]
const _: () = assert!(DPE_DCCM_STORAGE < memory_layout::DPE_SIZE as usize);

pub type PcrLogArray = [PcrLogEntry; PCR_LOG_MAX_COUNT];
pub type FuseLogArray = [FuseLogEntry; FUSE_LOG_MAX_COUNT];
pub type StashMeasurementArray = [MeasurementLogEntry; MEASUREMENT_MAX_COUNT];
#[cfg(feature = "runtime")]
pub type AuthManifestImageMetadataList =
    [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT];

#[derive(FromBytes, AsBytes, Zeroize)]
#[repr(C)]
pub struct PersistentData {
    pub manifest1: ImageManifest,
    reserved0: [u8; memory_layout::MAN1_SIZE as usize - size_of::<ImageManifest>()],

    pub manifest2: ImageManifest,
    reserved1: [u8; memory_layout::MAN2_SIZE as usize - size_of::<ImageManifest>()],

    pub fht: FirmwareHandoffTable,
    reserved2: [u8; memory_layout::FHT_SIZE as usize - size_of::<FirmwareHandoffTable>()],

    // TODO: Do we want to hide these fields from the FMC/runtime and force them
    // to go through the FHT addresses?
    pub ldevid_tbs: [u8; memory_layout::LDEVID_TBS_SIZE as usize],
    pub fmcalias_tbs: [u8; memory_layout::FMCALIAS_TBS_SIZE as usize],
    pub rtalias_tbs: [u8; memory_layout::RTALIAS_TBS_SIZE as usize],

    pub pcr_log: PcrLogArray,
    reserved3: [u8; memory_layout::PCR_LOG_SIZE as usize - size_of::<PcrLogArray>()],

    pub measurement_log: StashMeasurementArray,
    reserved4:
        [u8; memory_layout::MEASUREMENT_LOG_SIZE as usize - size_of::<StashMeasurementArray>()],

    pub fuse_log: FuseLogArray,
    reserved5: [u8; memory_layout::FUSE_LOG_SIZE as usize - size_of::<FuseLogArray>()],

    #[cfg(feature = "runtime")]
    pub dpe: DpeInstance,
    #[cfg(feature = "runtime")]
    pub context_tags: [u32; MAX_HANDLES],
    #[cfg(feature = "runtime")]
    pub context_has_tag: [U8Bool; MAX_HANDLES],
    #[cfg(feature = "runtime")]
    pub attestation_disabled: U8Bool,
    #[cfg(feature = "runtime")]
    reserved6: [u8; memory_layout::DPE_SIZE as usize - DPE_DCCM_STORAGE],
    #[cfg(not(feature = "runtime"))]
    dpe: [u8; memory_layout::DPE_SIZE as usize],
    #[cfg(feature = "runtime")]
    pub pcr_reset: PcrResetCounter,
    #[cfg(feature = "runtime")]
    reserved7: [u8; memory_layout::PCR_RESET_COUNTER_SIZE as usize - size_of::<PcrResetCounter>()],

    #[cfg(not(feature = "runtime"))]
    pcr_reset: [u8; memory_layout::PCR_RESET_COUNTER_SIZE as usize],

    #[cfg(feature = "runtime")]
    pub auth_manifest_image_metadata_col: AuthManifestImageMetadataCollection,
    #[cfg(feature = "runtime")]
    reserved9: [u8; memory_layout::AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize
        - size_of::<AuthManifestImageMetadataCollection>()],

    #[cfg(not(feature = "runtime"))]
    pub auth_manifest_image_metadata_col:
        [u8; memory_layout::AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize],
}
impl PersistentData {
    pub fn assert_matches_layout() {
        const P: *const PersistentData = memory_layout::MAN1_ORG as *const PersistentData;
        use memory_layout as layout;
        unsafe {
            assert_eq!(addr_of!((*P).manifest1) as u32, layout::MAN1_ORG);
            assert_eq!(addr_of!((*P).manifest2) as u32, layout::MAN2_ORG);
            assert_eq!(addr_of!((*P).fht) as u32, layout::FHT_ORG);
            assert_eq!(addr_of!((*P).ldevid_tbs) as u32, layout::LDEVID_TBS_ORG);
            assert_eq!(addr_of!((*P).fmcalias_tbs) as u32, layout::FMCALIAS_TBS_ORG);
            assert_eq!(addr_of!((*P).rtalias_tbs) as u32, layout::RTALIAS_TBS_ORG);
            assert_eq!(addr_of!((*P).pcr_log) as u32, memory_layout::PCR_LOG_ORG);
            assert_eq!(
                addr_of!((*P).measurement_log) as u32,
                memory_layout::MEASUREMENT_LOG_ORG
            );
            assert_eq!(addr_of!((*P).fuse_log) as u32, memory_layout::FUSE_LOG_ORG);
            assert_eq!(addr_of!((*P).dpe) as u32, memory_layout::DPE_ORG);
            assert_eq!(
                addr_of!((*P).pcr_reset) as u32,
                memory_layout::PCR_RESET_COUNTER_ORG
            );
            assert_eq!(
                addr_of!((*P).auth_manifest_image_metadata_col) as u32,
                memory_layout::AUTH_MAN_IMAGE_METADATA_LIST_ORG
            );
            assert_eq!(
                P.add(1) as u32,
                memory_layout::AUTH_MAN_IMAGE_METADATA_LIST_ORG
                    + memory_layout::AUTH_MAN_IMAGE_METADATA_MAX_SIZE
            );
        }
    }
}

pub struct PersistentDataAccessor {
    // This field is here to ensure that Self::new() is the only way
    // to create this type.
    _phantom: PhantomData<()>,
}
impl PersistentDataAccessor {
    /// # Safety
    ///
    /// It is unsound for more than one of these objects to exist simultaneously.
    /// DO NOT CALL FROM RANDOM APPLICATION CODE!
    pub unsafe fn new() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }

    /// # Safety
    ///
    /// DO NOT use unsafe code to modify any of this persistent memory
    /// as long as there exists any copies of the returned reference.
    #[inline(always)]
    pub fn get(&self) -> &PersistentData {
        // WARNING: The returned lifetime elided from `self` is critical for
        // safety. Do not change this API without review by a Rust expert.
        unsafe { ref_from_addr(memory_layout::MAN1_ORG) }
    }

    /// # Safety
    ///
    /// During the lifetime of the returned reference, it is unsound to use any
    /// unsafe mechanism to read or write to this memory.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut PersistentData {
        // WARNING: The returned lifetime elided from `self` is critical for
        // safety. Do not change this API without review by a Rust expert.
        unsafe { ref_mut_from_addr(memory_layout::MAN1_ORG) }
    }
}

#[inline(always)]
unsafe fn ref_from_addr<'a, T: FromBytes>(addr: u32) -> &'a T {
    // LTO should be able to optimize out the assertions to maintain panic_is_missing

    // dereferencing zero is undefined behavior
    assert!(addr != 0);
    assert!(addr as usize % core::mem::align_of::<T>() == 0);
    assert!(core::mem::size_of::<u32>() == core::mem::size_of::<*const T>());
    &*(addr as *const T)
}

#[inline(always)]
unsafe fn ref_mut_from_addr<'a, T: FromBytes>(addr: u32) -> &'a mut T {
    // LTO should be able to optimize out the assertions to maintain panic_is_missing

    // dereferencing zero is undefined behavior
    assert!(addr != 0);
    assert!(addr as usize % core::mem::align_of::<T>() == 0);
    assert!(core::mem::size_of::<u32>() == core::mem::size_of::<*const T>());
    &mut *(addr as *mut T)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout() {
        // NOTE: It's not good enough to test this from the host; we also need
        // to call assert_matches_layout() in a risc-v test.
        PersistentData::assert_matches_layout();
    }
}
