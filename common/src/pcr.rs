/*++
Licensed under the Apache-2.0 license.

File Name:

    pcr.rs

Abstract:

    PCR-related types.

--*/

use caliptra_drivers::PcrId;
use zerocopy::{AsBytes, FromBytes};

// PcrLogEntryId is used to identify the PCR entry and
// the size of the data in PcrLogEntry::pcr_data.
//
// For valid entries, it is also used as the index into the PCR log as per the formula:
//      log_entry_index = pcr_entry_id - 1
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrLogEntryId {
    Invalid = 0,
    DeviceLifecycle = 1,      // data size = 1 byte
    DebugLocked = 2,          // data size = 1 byte
    AntiRollbackDisabled = 3, // data size = 1 byte
    VendorPubKeyHash = 4,     // data size = 48 bytes
    OwnerPubKeyHash = 5,      // data size = 48 bytes
    VendorPubKeyIndex = 6,    // data size = 1 byte
    FmcTci = 7,               // data size = 48 bytes
    FmcSvn = 8,               // data size = 1 byte
    FmcFuseSvn = 9,           // data size = 1 byte
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
            6 => PcrLogEntryId::VendorPubKeyIndex,
            7 => PcrLogEntryId::FmcTci,
            8 => PcrLogEntryId::FmcSvn,
            _ => PcrLogEntryId::Invalid,
        }
    }
}

/// PCR log entry
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug)]
pub struct PcrLogEntry {
    /// Entry identifier
    pub id: u16,

    /// PCR to which the data is being extended to.
    pub pcr_id: u16,

    // PCR data
    pub pcr_data: [u32; 12],

    pub reserved: [u8; 4],
}

pub const RT_FW_CURRENT_PCR: PcrId = PcrId::PcrId3;
pub const RT_FW_JOURNEY_PCR: PcrId = PcrId::PcrId2;
