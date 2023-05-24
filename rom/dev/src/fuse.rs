/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    The file contains Fuse-related Implementations.

--*/
use caliptra_common::{FuseLogEntry, FuseLogEntryId};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use core::mem::size_of;
use zerocopy::AsBytes;

const FUSE_LOG_SIZE: usize = 1024;

extern "C" {
    static mut FUSE_LOG_ORG: [FuseLogEntry; FUSE_LOG_SIZE / size_of::<FuseLogEntry>()];
}

/// Log Fuse data
///
/// # Arguments
/// * `entry_id` - log entry ID
/// * `data` -  data To log to the fuse log
///
/// # Return Value
/// * `Ok(())` - Success
/// * `Err(GlobalErr::FuseLogInvalidEntryId)` - Invalid Fuse log entry ID
/// * `Err(GlobalErr::FuseLogUpsupportedDataLength)` - Unsupported data length
///
pub fn log_fuse_data(entry_id: FuseLogEntryId, data: &[u8]) -> CaliptraResult<()> {
    if entry_id == FuseLogEntryId::Invalid {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID);
    }

    if data.len() > 4 {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH);
    }

    // Create a FUSE log entry
    let mut log_entry = FuseLogEntry {
        entry_id: entry_id as u32,
        ..Default::default()
    };
    log_entry.log_data.as_bytes_mut()[..data.len()].copy_from_slice(data);

    let dst = unsafe { &mut FUSE_LOG_ORG[..] };
    dst[entry_id as usize - 1] = log_entry;

    Ok(())
}
