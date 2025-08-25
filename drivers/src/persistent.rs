// Licensed under the Apache-2.0 license

use core::{marker::PhantomData, mem::size_of, ptr::addr_of};

#[cfg(feature = "runtime")]
use caliptra_auth_man_types::{
    AuthManifestImageMetadata, AuthManifestImageMetadataCollection,
    AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::{ImageManifest, SHA512_DIGEST_BYTE_SIZE};
#[cfg(feature = "runtime")]
use dpe::{DpeInstance, U8Bool, MAX_HANDLES};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};
use zeroize::Zeroize;

#[cfg(feature = "runtime")]
use crate::sha2_512_384::SHA384_HASH_SIZE;
use crate::{
    fuse_log::FuseLogEntry,
    memory_layout,
    pcr_log::{MeasurementLogEntry, PcrLogEntry},
    DataVault, FirmwareHandoffTable, FmcAliasCsrs, Mldsa87PubKey, Mldsa87Signature,
};

#[cfg(feature = "runtime")]
use crate::pcr_reset::PcrResetCounter;

pub const ECC384_MAX_CSR_SIZE: usize = 512;
pub const MAN1_SIZE: u32 = 17 * 1024;
pub const MAN2_SIZE: u32 = 17 * 1024;
pub const DATAVAULT_MAX_SIZE: u32 = 15 * 1024;
pub const FHT_SIZE: u32 = 2 * 1024;
pub const IDEVID_MLDSA_PUB_KEY_MAX_SIZE: u32 = 3 * 1024;
pub const ECC_LDEVID_TBS_SIZE: u32 = 1024;
pub const ECC_FMCALIAS_TBS_SIZE: u32 = 1024;
pub const ECC_RTALIAS_TBS_SIZE: u32 = 1024;
pub const MLDSA_LDEVID_TBS_SIZE: u32 = 4 * 1024;
pub const MLDSA_FMCALIAS_TBS_SIZE: u32 = 4 * 1024;
pub const MLDSA_RTALIAS_TBS_SIZE: u32 = 4 * 1024;
pub const PCR_LOG_SIZE: u32 = 1024;
pub const MEASUREMENT_LOG_SIZE: u32 = 1024;
pub const FUSE_LOG_SIZE: u32 = 1024;
pub const DPE_SIZE: u32 = 5 * 1024;
pub const PCR_RESET_COUNTER_SIZE: u32 = 1024;
pub const AUTH_MAN_IMAGE_METADATA_MAX_SIZE: u32 = 10 * 1024;
pub const IDEVID_CSR_ENVELOP_SIZE: u32 = 9 * 1024;
pub const FMC_ALIAS_CSR_SIZE: u32 = 9 * 1024;
pub const MLDSA87_MAX_CSR_SIZE: usize = 7680;
pub const PCR_LOG_MAX_COUNT: usize = 17;
pub const FUSE_LOG_MAX_COUNT: usize = 62;
pub const MEASUREMENT_MAX_COUNT: usize = 8;
pub const MLDSA_SIGNATURE_SIZE: u32 = 4628;
pub const CMB_AES_KEY_SHARE_SIZE: u32 = 32;

#[cfg(feature = "runtime")]
const DPE_DCCM_STORAGE: usize = size_of::<DpeInstance>()
    + size_of::<u32>() * MAX_HANDLES
    + size_of::<U8Bool>() * MAX_HANDLES
    + size_of::<U8Bool>()
    + size_of::<U8Bool>();

#[cfg(feature = "runtime")]
const _: () = assert!(DPE_DCCM_STORAGE < DPE_SIZE as usize);

pub type PcrLogArray = [PcrLogEntry; PCR_LOG_MAX_COUNT];
pub type FuseLogArray = [FuseLogEntry; FUSE_LOG_MAX_COUNT];
pub type StashMeasurementArray = [MeasurementLogEntry; MEASUREMENT_MAX_COUNT];
#[cfg(feature = "runtime")]
pub type AuthManifestImageMetadataList =
    [AuthManifestImageMetadata; AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT];

#[derive(Clone, Immutable, IntoBytes, KnownLayout, TryFromBytes, Zeroize)]
#[repr(C)]
pub struct Ecc384IdevIdCsr {
    pub csr_len: u32,
    pub csr: [u8; ECC384_MAX_CSR_SIZE],
}

#[derive(Clone, FromBytes, Immutable, IntoBytes, KnownLayout, Zeroize)]
#[repr(C)]
pub struct Mldsa87IdevIdCsr {
    pub csr_len: u32,
    pub csr: [u8; MLDSA87_MAX_CSR_SIZE],
}

impl Default for Ecc384IdevIdCsr {
    fn default() -> Self {
        Self {
            csr_len: Self::UNPROVISIONED_CSR,
            csr: [0; ECC384_MAX_CSR_SIZE],
        }
    }
}

impl Default for Mldsa87IdevIdCsr {
    fn default() -> Self {
        Self {
            csr_len: Self::UNPROVISIONED_CSR,
            csr: [0; MLDSA87_MAX_CSR_SIZE],
        }
    }
}

macro_rules! impl_idevid_csr {
    ($type:ty, $size:expr) => {
        impl $type {
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
                if csr_len >= $size {
                    return Err(CaliptraError::ROM_IDEVID_INVALID_CSR);
                }

                let mut _self = Self {
                    csr_len: csr_len as u32,
                    csr: [0; $size],
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
    };
}

impl_idevid_csr!(Ecc384IdevIdCsr, ECC384_MAX_CSR_SIZE);
impl_idevid_csr!(Mldsa87IdevIdCsr, MLDSA87_MAX_CSR_SIZE);

pub type Hmac512Tag = [u8; SHA512_DIGEST_BYTE_SIZE];

pub const IDEVID_CSR_ENVELOP_MARKER: u32 = 0x43_5352;

/// Calipatra IDEVID CSR Envelope
#[repr(C)]
#[derive(Clone, IntoBytes, Immutable, KnownLayout, TryFromBytes, Zeroize)]
pub struct InitDevIdCsrEnvelope {
    /// Marker
    pub marker: u32,

    /// Size of the CSR Envelope
    pub size: u32,

    /// ECC CSR
    pub ecc_csr: Ecc384IdevIdCsr,

    /// MLDSA CSR
    pub mldsa_csr: Mldsa87IdevIdCsr,

    /// CSR MAC
    pub csr_mac: Hmac512Tag,
}

impl Default for InitDevIdCsrEnvelope {
    fn default() -> Self {
        InitDevIdCsrEnvelope {
            marker: IDEVID_CSR_ENVELOP_MARKER,
            size: size_of::<InitDevIdCsrEnvelope>() as u32,
            ecc_csr: Ecc384IdevIdCsr::default(),
            mldsa_csr: Mldsa87IdevIdCsr::default(),
            csr_mac: [0u8; SHA512_DIGEST_BYTE_SIZE],
        }
    }
}

pub mod fmc_alias_csr {
    use super::*;

    #[derive(Clone, TryFromBytes, IntoBytes, KnownLayout, Zeroize)]
    #[repr(C)]
    pub struct FmcAliasCsrs {
        pub ecc_csr_len: u32,
        pub ecc_csr: [u8; ECC384_MAX_CSR_SIZE],
        pub mldsa_csr_len: u32,
        pub mldsa_csr: [u8; MLDSA87_MAX_CSR_SIZE],
    }

    impl Default for FmcAliasCsrs {
        fn default() -> Self {
            Self {
                ecc_csr_len: Self::UNPROVISIONED_CSR,
                ecc_csr: [0; ECC384_MAX_CSR_SIZE],
                mldsa_csr_len: Self::UNPROVISIONED_CSR,
                mldsa_csr: [0; MLDSA87_MAX_CSR_SIZE],
            }
        }
    }

    impl FmcAliasCsrs {
        /// The `csr_len` field is set to this constant when a ROM image supports CSR generation but
        /// the CSR generation flag was not enabled.
        ///
        /// This is used by the runtime to distinguish ROM images that support CSR generation from
        /// ones that do not.
        ///
        /// u32::MAX is too large to be a valid CSR, so we use it to encode this state.
        pub const UNPROVISIONED_CSR: u32 = u32::MAX;

        /// Get the ECC CSR
        pub fn get_ecc_csr(&self) -> Option<&[u8]> {
            self.ecc_csr.get(..self.ecc_csr_len as usize)
        }

        /// Get the MLDSA CSR
        pub fn get_mldsa_csr(&self) -> Option<&[u8]> {
            self.mldsa_csr.get(..self.mldsa_csr_len as usize)
        }

        /// Get the length of the ECC CSR in bytes.
        pub fn get_ecc_csr_len(&self) -> u32 {
            self.ecc_csr_len
        }

        /// Get the length of the MLDSA CSR in bytes.
        pub fn get_mldsa_csr_len(&self) -> u32 {
            self.mldsa_csr_len
        }

        /// Check if the ECC CSR was unprovisioned
        pub fn is_ecc_csr_unprovisioned(&self) -> bool {
            self.ecc_csr_len == Self::UNPROVISIONED_CSR
        }

        /// Check if the MLDSA CSR was unprovisioned
        pub fn is_mldsa_csr_unprovisioned(&self) -> bool {
            self.mldsa_csr_len == Self::UNPROVISIONED_CSR
        }
    }
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Zeroize)]
#[repr(C)]
pub struct DOT_OWNER_PK_HASH {
    pub owner_pk_hash: [u32; 12],
    pub valid: bool,
    reserved: [u8; 3],
}

#[derive(TryFromBytes, IntoBytes, KnownLayout, Zeroize)]
#[repr(C)]
pub struct PersistentData {
    pub manifest1: ImageManifest,
    reserved0: [u8; MAN1_SIZE as usize - size_of::<ImageManifest>()],

    pub manifest2: ImageManifest,
    reserved1: [u8; MAN2_SIZE as usize - size_of::<ImageManifest>()],

    #[zeroize(skip)]
    pub data_vault: DataVault,
    reserved1_1: [u8; DATAVAULT_MAX_SIZE as usize - size_of::<DataVault>()],

    pub fht: FirmwareHandoffTable,
    reserved2: [u8; FHT_SIZE as usize - size_of::<FirmwareHandoffTable>()],

    pub idevid_mldsa_pub_key: Mldsa87PubKey,
    reserved2_1: [u8; IDEVID_MLDSA_PUB_KEY_MAX_SIZE as usize - size_of::<Mldsa87PubKey>()],

    pub ecc_ldevid_tbs: [u8; ECC_LDEVID_TBS_SIZE as usize],
    pub ecc_fmcalias_tbs: [u8; ECC_FMCALIAS_TBS_SIZE as usize],
    pub ecc_rtalias_tbs: [u8; ECC_RTALIAS_TBS_SIZE as usize],
    pub mldsa_ldevid_tbs: [u8; MLDSA_LDEVID_TBS_SIZE as usize],
    pub mldsa_fmcalias_tbs: [u8; MLDSA_FMCALIAS_TBS_SIZE as usize],
    pub mldsa_rtalias_tbs: [u8; MLDSA_RTALIAS_TBS_SIZE as usize],

    pub rtalias_mldsa_tbs_size: u16,
    reserved2_2: [u8; 2],
    pub rt_dice_mldsa_sign: Mldsa87Signature,

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
    pub runtime_cmd_active: U8Bool,
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
    pub auth_manifest_digest: [u32; SHA384_HASH_SIZE / 4],
    #[cfg(feature = "runtime")]
    reserved9: [u8; AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize
        - (SHA384_HASH_SIZE + size_of::<AuthManifestImageMetadataCollection>())],

    #[cfg(not(feature = "runtime"))]
    pub auth_manifest_image_metadata_col: [u8; AUTH_MAN_IMAGE_METADATA_MAX_SIZE as usize],

    pub idevid_csr_envelop: InitDevIdCsrEnvelope,
    reserved10: [u8; IDEVID_CSR_ENVELOP_SIZE as usize - size_of::<InitDevIdCsrEnvelope>()],

    pub fmc_alias_csr: FmcAliasCsrs,
    reserved11: [u8; FMC_ALIAS_CSR_SIZE as usize - size_of::<FmcAliasCsrs>()],

    pub cmb_aes_key_share0: [u8; 32],
    pub cmb_aes_key_share1: [u8; 32],

    pub dot_owner_pk_hash: DOT_OWNER_PK_HASH,

    pub cleared_non_fatal_fw_error: u32,
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
                addr_of!((*P).data_vault) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += DATAVAULT_MAX_SIZE;
            assert_eq!(
                addr_of!((*P).fht) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += FHT_SIZE;
            assert_eq!(
                addr_of!((*P).idevid_mldsa_pub_key) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += IDEVID_MLDSA_PUB_KEY_MAX_SIZE;
            assert_eq!(
                addr_of!((*P).ecc_ldevid_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += ECC_LDEVID_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).ecc_fmcalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += ECC_FMCALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).ecc_rtalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += ECC_RTALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).mldsa_ldevid_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MLDSA_LDEVID_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).mldsa_fmcalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MLDSA_FMCALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).mldsa_rtalias_tbs) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MLDSA_RTALIAS_TBS_SIZE;
            assert_eq!(
                addr_of!((*P).rtalias_mldsa_tbs_size) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += 4;
            assert_eq!(
                addr_of!((*P).rt_dice_mldsa_sign) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += MLDSA_SIGNATURE_SIZE;
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
                addr_of!((*P).idevid_csr_envelop) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );

            persistent_data_offset += IDEVID_CSR_ENVELOP_SIZE;
            assert_eq!(
                addr_of!((*P).fmc_alias_csr) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );
            persistent_data_offset += FMC_ALIAS_CSR_SIZE;
            assert_eq!(
                addr_of!((*P).cmb_aes_key_share0) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );
            persistent_data_offset += CMB_AES_KEY_SHARE_SIZE;
            assert_eq!(
                addr_of!((*P).cmb_aes_key_share1) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
            );
            persistent_data_offset += CMB_AES_KEY_SHARE_SIZE;
            assert_eq!(
                addr_of!((*P).dot_owner_pk_hash) as u32,
                memory_layout::PERSISTENT_DATA_ORG + persistent_data_offset
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
