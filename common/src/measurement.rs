/*++
Licensed under the Apache-2.0 license.

File Name:

    measurement.rs

Abstract:

    Mailbox measurement related types.

--*/
use zerocopy::{AsBytes, FromBytes};

/// Caliptra DPE Measurement    
#[repr(C)]
#[derive(AsBytes, FromBytes, Default, Debug)]
pub struct StashMeasurement {
    /// Checksum
    pub checksum: u32,

    /// Metadata
    pub metadata: [u8; 4],

    /// Measurement
    pub measurement: [u32; 12],
}
