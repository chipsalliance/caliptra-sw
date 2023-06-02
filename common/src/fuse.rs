/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    Fuse-related Types.

--*/

use zerocopy::{AsBytes, FromBytes};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum FuseLogEntryId {
    Invalid = 0,
    VendorPubKeyIndex = 1,      // 4 bytes  (From Manifest)
    VendorPubKeyRevocation = 2, // 4 bytes  (From Fuse)
    ManifestFmcSvn = 3,         // 4 bytes
    ManifestFmcMinSvn = 4,      // 4 bytes
    FuseFmcSvn = 5,             // 4 bytes
    ManifestRtSvn = 6,          // 4 bytes
    ManifestRtMinSvn = 7,       // 4 bytes
    FuseRtSvn = 8,              // 4 bytes
}

impl From<u32> for FuseLogEntryId {
    fn from(id: u32) -> FuseLogEntryId {
        match id {
            1 => FuseLogEntryId::VendorPubKeyIndex,
            2 => FuseLogEntryId::VendorPubKeyRevocation,
            3 => FuseLogEntryId::ManifestFmcSvn,
            4 => FuseLogEntryId::ManifestFmcMinSvn,
            5 => FuseLogEntryId::FuseFmcSvn,
            6 => FuseLogEntryId::ManifestRtSvn,
            7 => FuseLogEntryId::ManifestRtMinSvn,
            8 => FuseLogEntryId::FuseRtSvn,
            _ => FuseLogEntryId::Invalid,
        }
    }
}

/// Fuse log entry
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug)]
pub struct FuseLogEntry {
    /// Entry identifier
    pub entry_id: u32,

    pub log_data: [u32; 1],

    pub reserved: [u32; 2],
}
