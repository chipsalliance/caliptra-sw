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
    VendorEccPubKeyIndex = 1,       // 4 bytes  (From Manifest)
    VendorEccPubKeyRevocation = 2,  // 4 bytes  (From Fuse)
    ManifestFmcSvn = 3,             // 4 bytes
    ManifestFmcMinSvn = 4,          // 4 bytes
    FuseFmcSvn = 5,                 // 4 bytes
    ManifestRtSvn = 6,              // 4 bytes
    ManifestRtMinSvn = 7,           // 4 bytes
    FuseRtSvn = 8,                  // 4 bytes
    VendorLmsPubKeyIndex = 9,       // 4 bytes  (From Manifest)
    VendorLmsPubKeyRevocation = 10, // 4 bytes  (From Fuse)
    OwnerLmsPubKeyIndex = 11,       // 4 bytes  (From Manifest)
}

impl From<u32> for FuseLogEntryId {
    fn from(id: u32) -> FuseLogEntryId {
        match id {
            1 => FuseLogEntryId::VendorEccPubKeyIndex,
            2 => FuseLogEntryId::VendorEccPubKeyRevocation,
            3 => FuseLogEntryId::ManifestFmcSvn,
            4 => FuseLogEntryId::ManifestFmcMinSvn,
            5 => FuseLogEntryId::FuseFmcSvn,
            6 => FuseLogEntryId::ManifestRtSvn,
            7 => FuseLogEntryId::ManifestRtMinSvn,
            8 => FuseLogEntryId::FuseRtSvn,
            9 => FuseLogEntryId::VendorLmsPubKeyIndex,
            10 => FuseLogEntryId::VendorLmsPubKeyRevocation,
            11 => FuseLogEntryId::OwnerLmsPubKeyIndex,
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
