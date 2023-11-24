/*++
Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    PCR-related types.

--*/

use crate::PcrId;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

pub const PCR_ID_FMC_CURRENT: PcrId = PcrId::PcrId0;
pub const PCR_ID_FMC_JOURNEY: PcrId = PcrId::PcrId1;
pub const PCR_ID_STASH_MEASUREMENT: PcrId = PcrId::PcrId31;

// PcrLogEntryId is used to identify the PCR entry and
// the size of the data in PcrLogEntry::pcr_data.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrLogEntryId {
    Invalid = 0,
    DeviceStatus = 1,     // data size = 9 bytes
    VendorPubKeyHash = 2, // data size = 48 bytes
    OwnerPubKeyHash = 3,  // data size = 48 bytes
    FmcTci = 4,           // data size = 48 bytes
    StashMeasurement = 5, // data size = 48 bytes
    RtTci = 6,            // data size = 48 bytes
    FwImageManifest = 7,  // data size = 48 bytes
}

impl From<u16> for PcrLogEntryId {
    /// Converts to this type from the input type.
    fn from(id: u16) -> PcrLogEntryId {
        match id {
            1 => PcrLogEntryId::DeviceStatus,
            2 => PcrLogEntryId::VendorPubKeyHash,
            3 => PcrLogEntryId::OwnerPubKeyHash,
            4 => PcrLogEntryId::FmcTci,
            5 => PcrLogEntryId::StashMeasurement,
            6 => PcrLogEntryId::RtTci,
            7 => PcrLogEntryId::FwImageManifest,
            _ => PcrLogEntryId::Invalid,
        }
    }
}

/// PCR log entry
#[repr(C)]
#[derive(AsBytes, Clone, Copy, Debug, Default, FromBytes, Zeroize)]
pub struct PcrLogEntry {
    /// Entry identifier
    pub id: u16,

    pub reserved0: [u8; 2],

    /// Bitmask indicating the PCRs to which the data is being extended to.
    pub pcr_ids: u32,

    // PCR data
    pub pcr_data: [u32; 12],
}

impl PcrLogEntry {
    pub fn measured_data(&self) -> &[u8] {
        let data_len = match PcrLogEntryId::from(self.id) {
            PcrLogEntryId::Invalid => 0,
            PcrLogEntryId::DeviceStatus => 9,
            PcrLogEntryId::VendorPubKeyHash => 48,
            PcrLogEntryId::OwnerPubKeyHash => 48,
            PcrLogEntryId::FmcTci => 48,
            PcrLogEntryId::StashMeasurement => 48,
            PcrLogEntryId::RtTci => 48,
            PcrLogEntryId::FwImageManifest => 48,
        };

        &self.pcr_data.as_bytes()[..data_len]
    }
}

/// Measurement log entry
#[repr(C)]
#[derive(AsBytes, Clone, Copy, Debug, Default, FromBytes, Zeroize)]
pub struct MeasurementLogEntry {
    pub pcr_entry: PcrLogEntry,
    pub metadata: [u8; 4],
    pub context: [u32; 12],
    pub svn: u32,
    pub reserved0: [u8; 4],
}

pub const RT_FW_CURRENT_PCR: PcrId = PcrId::PcrId2;
pub const RT_FW_JOURNEY_PCR: PcrId = PcrId::PcrId3;
