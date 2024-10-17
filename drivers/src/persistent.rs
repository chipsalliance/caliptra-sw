// Licensed under the Apache-2.0 license

use core::{marker::PhantomData, mem::size_of, ptr::addr_of};

#[cfg(feature = "runtime")]
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection,
    AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::ImageManifest;
#[cfg(feature = "runtime")]
use dpe::{DpeInstance, U8Bool, MAX_HANDLES};
use zerocopy::{IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

use crate::{
    fuse_log::FuseLogEntry,
    memory_layout,
    pcr_log::{MeasurementLogEntry, PcrLogEntry},
    FirmwareHandoffTable,
};

#[cfg(feature = "runtime")]
use crate::pcr_reset::PcrResetCounter;

pub const MAX_CSR_SIZE: usize = 512;
pub const MAN1_SIZE: u32 = 6 * 1024;
pub const MAN2_SIZE: u32 = 6 * 1024;
pub const FHT_SIZE: u32 = 2 * 1024;
pub const LDEVID_TBS_SIZE: u32 = 1024;
pub const FMCALIAS_TBS_SIZE: u32 = 1024;
pub const RTALIAS_TBS_SIZE: u32 = 1024;
pub const PCR_LOG_SIZE: u32 = 1024;
pub const MEASUREMENT_LOG_SIZE: u32 = 1024;
pub const FUSE_LOG_SIZE: u32 = 1024;
pub const DPE_SIZE: u32 = 5 * 1024;
pub const PCR_RESET_COUNTER_SIZE: u32 = 1024;
pub const AUTH_MAN_IMAGE_METADATA_MAX_SIZE: u32 = 7 * 1024;
pub const IDEVID_CSR_SIZE: u32 = 1024;
pub const RESERVED_MEMORY_SIZE: u32 = 19 * 1024;

pub const PCR_LOG_MAX_COUNT: usize = 17;
pub const FUSE_LOG_MAX_COUNT: usize = 62;
pub const MEASUREMENT_MAX_COUNT: usize = 8;

#[cfg(feature = "runtime")]
const DPE_DCCM_STORAGE: usize = size_of::<DpeInstance>()
    + size_of::<u32>() * MAX_HANDLES
    + size_of::<U8Bool>() * MAX_HANDLES
    + size_of::<U8Bool>();

#[cfg(feature = "runtime")]
const _: () = assert!(DPE_DCCM_STORAGE < DPE_SIZE as usize);

pub type PcrLogArray = [PcrLogEntry; PCR_LOG_MAX_COUNT];
pub type FuseLogArray = [FuseLogEntry; FUSE_LOG_MAX_COUNT];
pub type StashMeasurementArray = [MeasurementLogEntry; MEASUREMENT_MAX_COUNT];
#[cfg(feature = "runtime")]
pub type AuthManifestImageMetadataList =
    [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT];

const _: () = assert!(MAX_CSR_SIZE < IDEVID_CSR_SIZE as usize);

#[derive(Clone, TryFromBytes, IntoBytes, Zeroize)]
#[repr(C)]
pub struct IdevIdCsr {
    csr_len: u32,
    csr: [u8; MAX_CSR_SIZE],
}

impl Default for IdevIdCsr {
    fn default() -> Self {
        Self {
            csr_len: Self::UNPROVISIONED_CSR,
            csr: [0; MAX_CSR_SIZE],
        }
    }
}

impl IdevIdCsr {
    /// The `csr_len` field is set to this constant when a ROM image supports CSR generation but
    /// the CSR generation flag was not enabled.
    ///
    /// This is used by the runtime to distinguish ROM images that support CSR generation from
    /// ones that do not.
    ///
    /// u32::MAX is too large to be a valid CSR, so we use it to encode this state.
    pub const UNPROVISIONED_CSR: u32 = u32::MAX;

    /// Get the CSR buffer
    pub fn get(&self) -> Option<&[u8]> {
        self.csr.get(..self.csr_len as usize)
    }

    /// Create `Self` from a csr slice. `csr_len` MUST be the actual length of the csr.
    pub fn new(csr_buf: &[u8], csr_len: usize) -> CaliptraResult<Self> {
        if csr_len >= MAX_CSR_SIZE {
            return Err(CaliptraError::ROM_IDEVID_INVALID_CSR);
        }

        let mut _self = Self {
            csr_len: csr_len as u32,
            csr: [0; MAX_CSR_SIZE],
        };
        _self.csr[..csr_len].copy_from_slice(&csr_buf[..csr_len]);

        Ok(_self)
    }

    /// Get the length of the CSR in bytes.
    pub fn get_csr_len(&self) -> u32 {
        self.csr_len
    }

    /// Check if the CSR was unprovisioned
    pub fn is_unprovisioned(&self) -> bool {
        self.csr_len == Self::UNPROVISIONED_CSR
    }
}

const _: () = assert!(size_of::<PersistentData>() == memory_layout::PERSISTENT_DATA_SIZE as usize);
const _: () = assert!(size_of::<ImageManifest>() <= MAN1_SIZE as usize);
const _: () = assert!(size_of::<ImageManifest>() <= MAN2_SIZE as usize);
const _: () = assert!(size_of::<FirmwareHandoffTable>() <= FHT_SIZE as usize);
const _: () = assert!(size_of::<PcrLogArray>() <= PCR_LOG_SIZE as usize);
const _: () = assert!(size_of::<StashMeasurementArray>() <= MEASUREMENT_LOG_SIZE as usize);
const _: () = assert!(size_of::<FuseLogArray>() <= FUSE_LOG_SIZE as usize);
#[cfg(feature = "runtime")]
const _: () = assert!(size_of::<PcrResetCounter>() <= PCR_RESET_COUNTER_SIZE as usize);
#[cfg(feature = "runtime")]
const _: () = assert!(
    size_of::<AuthManifestImageMetadataCollection>() <= AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize
);
const _: () = assert!(size_of::<IdevIdCsr>() <= IDEVID_CSR_SIZE as usize);

#[derive(TryFromBytes, IntoBytes, KnownLayout, Zeroize)]
#[repr(C)]
pub struct PersistentData {
    pub manifest1: ImageManifest,
    reserved0: [u8; MAN1_SIZE as usize - size_of::<ImageManifest>()],

    pub manifest2: ImageManifest,
    reserved1: [u8; MAN2_SIZE as usize - size_of::<ImageManifest>()],

    pub fht: FirmwareHandoffTable,
    reserved2: [u8; FHT_SIZE as usize - size_of::<FirmwareHandoffTable>()],

    // TODO: Do we want to hide these fields from the FMC/runtime and force them
    // to go through the FHT addresses?
    pub ldevid_tbs: [u8; LDEVID_TBS_SIZE as usize],
    pub fmcalias_tbs: [u8; FMCALIAS_TBS_SIZE as usize],
    pub rtalias_tbs: [u8; RTALIAS_TBS_SIZE as usize],

    pub pcr_log: PcrLogArray,
    reserved3: [u8; PCR_LOG_SIZE as usize - size_of::<PcrLogArray>()],

    pub measurement_log: StashMeasurementArray,
    reserved4: [u8; MEASUREMENT_LOG_SIZE as usize - size_of::<StashMeasurementArray>()],

    pub fuse_log: FuseLogArray,
    reserved5: [u8; FUSE_LOG_SIZE as usize - size_of::<FuseLogArray>()],

    #[cfg(feature = "runtime")]
    pub dpe: DpeInstance,
    #[cfg(feature = "runtime")]
    pub context_tags: [u32; MAX_HANDLES],
    #[cfg(feature = "runtime")]
    pub context_has_tag: [U8Bool; MAX_HANDLES],
    #[cfg(feature = "runtime")]
    pub attestation_disabled: U8Bool,
    #[cfg(feature = "runtime")]
    reserved6: [u8; DPE_SIZE as usize - DPE_DCCM_STORAGE],
    #[cfg(not(feature = "runtime"))]
    dpe: [u8; DPE_SIZE as usize],
    #[cfg(feature = "runtime")]
    pub pcr_reset: PcrResetCounter,
    #[cfg(feature = "runtime")]
    reserved7: [u8; PCR_RESET_COUNTER_SIZE as usize - size_of::<PcrResetCounter>()],

    #[cfg(not(feature = "runtime"))]
    pcr_reset: [u8; PCR_RESET_COUNTER_SIZE as usize],

    #[cfg(feature = "runtime")]
    pub auth_manifest_image_metadata_col: AuthManifestImageMetadataCollection,
    #[cfg(feature = "runtime")]
    reserved9: [u8; AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize
        - size_of::<AuthManifestImageMetadataCollection>()],

    #[cfg(not(feature = "runtime"))]
    pub auth_manifest_image_metadata_col: [u8; AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize],

    pub idevid_csr: IdevIdCsr,
    reserved10: [u8; IDEVID_CSR_SIZE as usize - size_of::<IdevIdCsr>()],

    // Reserved memory for future objects.
    // New objects should always source memory from this range.
    // Taking memory from this reserve does NOT break hitless updates.
    pub reserved_memory: [u8; RESERVED_MEMORY_SIZE as usize],
}

impl PersistentData {
    pub fn assert_matches_layout() {
        const P: *const PersistentData =
            memory_layout::PERSISTENT_DATA_ORG as *const PersistentData;
        unsafe {
            let mut persistent_data_offset = 0;
            assert_eq!(
                addr_of!((*P).manifest1) as u32,
                memory_layout::PERSISTENT_DATA_ORG
            );
            persistent_data_offset += MAN1_SIZE;
            assert_eq!(
                addr_of!((*P).manifest2) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MAN2_SIZE;
            assert_eq!(
                addr_of!((*P).fht) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += FHT_SIZE;
            assert_eq!(
                addr_of!((*P).ldevid_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += LDEVID_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).fmcalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += FMCALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).rtalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += RTALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).pcr_log) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += PCR_LOG_SIZE;
            assert_eq!(
                addr_of!((*P).measurement_log) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MEASUREMENT_LOG_SIZE;
            assert_eq!(
                addr_of!((*P).fuse_log) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += FUSE_LOG_SIZE;
            assert_eq!(
                addr_of!((*P).dpe) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += DPE_SIZE;
            assert_eq!(
                addr_of!((*P).pcr_reset) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += PCR_RESET_COUNTER_SIZE;
            assert_eq!(
                addr_of!((*P).auth_manifest_image_metadata_col) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += AUTH_MAN_IMAGE_METADATA_MAX_SIZE;
            assert_eq!(
                addr_of!((*P).idevid_csr) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += IDEVID_CSR_SIZE;
            assert_eq!(
                addr_of!((*P).reserved_memory) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            assert_eq!(
                P.add(1) as u32,
                memory_layout::PERSISTENT_DATA_ORG + memory_layout::PERSISTENT_DATA_SIZE
            );
            assert_eq!(P.add(1) as u32, memory_layout::DATA_ORG);
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
        unsafe { ref_from_addr(memory_layout::PERSISTENT_DATA_ORG) }
    }

    /// # Safety
    ///
    /// During the lifetime of the returned reference, it is unsound to use any
    /// unsafe mechanism to read or write to this memory.
    #[inline(always)]
    pub fn get_mut(&mut self) -> &mut PersistentData {
        // WARNING: The returned lifetime elided from `self` is critical for
        // safety. Do not change this API without review by a Rust expert.
        unsafe { ref_mut_from_addr(memory_layout::PERSISTENT_DATA_ORG) }
    }
}

#[inline(always)]
unsafe fn ref_from_addr<'a, T: TryFromBytes>(addr: u32) -> &'a T {
    // LTO should be able to optimize out the assertions to maintain panic_is_missing

    // dereferencing zero is undefined behavior
    assert!(addr != 0);
    assert!(addr as usize % core::mem::align_of::<T>() == 0);
    assert!(core::mem::size_of::<u32>() == core::mem::size_of::<*const T>());
    &*(addr as *const T)
}

#[inline(always)]
unsafe fn ref_mut_from_addr<'a, T: TryFromBytes>(addr: u32) -> &'a mut T {
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
