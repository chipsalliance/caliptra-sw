/*++
Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    PCR-related types.

--*/

use crate::PcrId;
use zerocopy::{AsBytes, FromBytes};

pub const PCR_ID_FMC_CURRENT: PcrId = PcrId::PcrId0;
pub const PCR_ID_FMC_JOURNEY: PcrId = PcrId::PcrId1;
pub const PCR_ID_STASH_MEASUREMENT: PcrId = PcrId::PcrId31;

// PcrLogEntryId is used to identify the PCR entry and
// the size of the data in PcrLogEntry::pcr_data.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrLogEntryId {
    Invalid = 0,
    DeviceLifecycle = 1,       // data size = 1 byte
    DebugLocked = 2,           // data size = 1 byte
    AntiRollbackDisabled = 3,  // data size = 1 byte
    VendorPubKeyHash = 4,      // data size = 48 bytes
    OwnerPubKeyHash = 5,       // data size = 48 bytes
    EccVendorPubKeyIndex = 6,  // data size = 1 byte
    FmcTci = 7,                // data size = 48 bytes
    FmcSvn = 8,                // data size = 1 byte
    FmcFuseSvn = 9,            // data size = 1 byte
    LmsVendorPubKeyIndex = 10, // data size = 1 byte
    RomVerifyConfig = 11,      // data size = 1 byte
    StashMeasurement = 12,     // data size = 48 bytes
}

impl From<u16> for PcrLogEntryId {
    /// Converts to this type from the input type.
    fn from(id: u16) -> PcrLogEntryId {
        match id {
            1 => PcrLogEntryId::DeviceLifecycle,
            2 => PcrLogEntryId::DebugLocked,
            3 => PcrLogEntryId::AntiRollbackDisabled,
            4 => PcrLogEntryId::VendorPubKeyHash,
            5 => PcrLogEntryId::OwnerPubKeyHash,
            6 => PcrLogEntryId::EccVendorPubKeyIndex,
            7 => PcrLogEntryId::FmcTci,
            8 => PcrLogEntryId::FmcSvn,
            9 => PcrLogEntryId::FmcFuseSvn,
            10 => PcrLogEntryId::LmsVendorPubKeyIndex,
            11 => PcrLogEntryId::RomVerifyConfig,
            12 => PcrLogEntryId::StashMeasurement,
            _ => PcrLogEntryId::Invalid,
        }
    }
}

/// PCR log entry
#[repr(C)]
#[derive(AsBytes, Clone, Copy, Debug, Default, FromBytes)]
pub struct PcrLogEntry {
    /// Entry identifier
    pub id: u16,

    pub reserved0: [u8; 2],

    /// Bitmask indicating the PCRs to which the data is being extended to.
    pub pcr_ids: u32,

    // PCR data
    pub pcr_data: [u32; 12],

    // PCR Metadata
    pub metadata: [u8; 4],
}

impl PcrLogEntry {
    pub fn measured_data(&self) -> &[u8] {
        let data_len = match PcrLogEntryId::from(self.id) {
            PcrLogEntryId::Invalid => 0,
            PcrLogEntryId::DeviceLifecycle => 1,
            PcrLogEntryId::DebugLocked => 1,
            PcrLogEntryId::AntiRollbackDisabled => 1,
            PcrLogEntryId::VendorPubKeyHash => 48,
            PcrLogEntryId::OwnerPubKeyHash => 48,
            PcrLogEntryId::EccVendorPubKeyIndex => 1,
            PcrLogEntryId::FmcTci => 48,
            PcrLogEntryId::FmcSvn => 1,
            PcrLogEntryId::FmcFuseSvn => 1,
            PcrLogEntryId::LmsVendorPubKeyIndex => 1,
            PcrLogEntryId::RomVerifyConfig => 1,
            PcrLogEntryId::StashMeasurement => 48,
        };

        &self.pcr_data.as_bytes()[..data_len]
    }
}

pub const RT_FW_CURRENT_PCR: PcrId = PcrId::PcrId2;
pub const RT_FW_JOURNEY_PCR: PcrId = PcrId::PcrId3;
