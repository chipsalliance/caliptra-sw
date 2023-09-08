// Licensed under the Apache-2.0 license

use core::{marker::PhantomData, mem::size_of, ptr::addr_of};

use caliptra_image_types::ImageManifest;
use zerocopy::{AsBytes, FromBytes};

use crate::{fuse_log::FuseLogEntry, memory_layout, pcr_log::PcrLogEntry, FirmwareHandoffTable};

pub type PcrLogArray = [PcrLogEntry; 17];
pub type FuseLogArray = [FuseLogEntry; 62];

#[derive(FromBytes, AsBytes)]
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
    reserved3: [u8; 4],

    pub fuse_log: FuseLogArray,
    reserved4: [u8; 4],
}
impl PersistentData {
    pub fn assert_matches_layout() {
        const P: *const PersistentData = memory_layout::DCCM_ORG as *const PersistentData;
        use memory_layout as layout;
        unsafe {
            assert_eq!(addr_of!((*P).manifest1) as u32, layout::MAN1_ORG);
            assert_eq!(addr_of!((*P).manifest2) as u32, layout::MAN2_ORG);
            assert_eq!(addr_of!((*P).fht) as u32, layout::FHT_ORG);
            assert_eq!(addr_of!((*P).ldevid_tbs) as u32, layout::LDEVID_TBS_ORG);
            assert_eq!(addr_of!((*P).fmcalias_tbs) as u32, layout::FMCALIAS_TBS_ORG);
            assert_eq!(addr_of!((*P).rtalias_tbs) as u32, layout::RTALIAS_TBS_ORG);
            assert_eq!(addr_of!((*P).pcr_log) as u32, memory_layout::PCR_LOG_ORG);
            assert_eq!(addr_of!((*P).fuse_log) as u32, memory_layout::FUSE_LOG_ORG);
            assert_eq!(P.add(1) as u32, memory_layout::BOOT_STATUS_ORG);
        }
    }

    pub fn zeroize(&mut self) {
        self.as_bytes_mut().fill(0);
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
        unsafe { ref_from_addr(memory_layout::DCCM_ORG) }
    }

    /// # Safety
    ///
    /// During the lifetime of the returned reference, it is unsound to use any
    /// unsafe mechanism to read or write to this memory.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut PersistentData {
        // WARNING: The returned lifetime elided from `self` is critical for
        // safety. Do not change this API without review by a Rust expert.
        unsafe { ref_mut_from_addr(memory_layout::DCCM_ORG) }
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
