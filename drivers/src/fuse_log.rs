/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    Fuse-related Types.

--*/

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
use zeroize::Zeroize;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum FuseLogEntryId {
    Invalid = 0,
    VendorEccPubKeyIndex = 1,      // 4 bytes  (From Manifest)
    VendorEccPubKeyRevocation = 2, // 4 bytes  (From Fuse)
    ColdBootFwSvn = 3,             // 4 bytes
    ManifestReserved0 = 4,         // 4 bytes
    #[deprecated]
    _DeprecatedFuseFmcSvn = 5, // 4 bytes
    ManifestFwSvn = 6,             // 4 bytes
    ManifestReserved1 = 7,         // 4 bytes
    FuseFwSvn = 8,                 // 4 bytes
    VendorPqcPubKeyIndex = 9,      // 4 bytes  (From Manifest)
    VendorPqcPubKeyRevocation = 10, // 4 bytes  (From Fuse)
}

impl From<u32> for FuseLogEntryId {
    #[allow(deprecated)]
    fn from(id: u32) -> FuseLogEntryId {
        match id {
            1 => FuseLogEntryId::VendorEccPubKeyIndex,
            2 => FuseLogEntryId::VendorEccPubKeyRevocation,
            3 => FuseLogEntryId::ColdBootFwSvn,
            4 => FuseLogEntryId::ManifestReserved0,
            5 => FuseLogEntryId::_DeprecatedFuseFmcSvn,
            6 => FuseLogEntryId::ManifestFwSvn,
            7 => FuseLogEntryId::ManifestReserved1,
            8 => FuseLogEntryId::FuseFwSvn,
            9 => FuseLogEntryId::VendorPqcPubKeyIndex,
            10 => FuseLogEntryId::VendorPqcPubKeyRevocation,
            _ => FuseLogEntryId::Invalid,
        }
    }
}

/// Fuse log entry
#[repr(C)]
#[derive(IntoBytes, Clone, Copy, Debug, Default, FromBytes, KnownLayout, Immutable, Zeroize)]
pub struct FuseLogEntry {
    /// Entry identifier
    pub entry_id: u32,

    pub log_data: [u32; 1],

    pub reserved: [u32; 2],
}
