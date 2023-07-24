/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    The file contains Fuse-related Implementations.

--*/
use caliptra_common::{
    memory_layout::{FUSE_LOG_ORG, FUSE_LOG_SIZE},
    FuseLogEntry, FuseLogEntryId,
};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::AsBytes;

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

    let dst: &mut [FuseLogEntry] = unsafe {
        let ptr = FUSE_LOG_ORG as *mut FuseLogEntry;
        core::slice::from_raw_parts_mut(ptr, FUSE_LOG_SIZE / core::mem::size_of::<FuseLogEntry>())
    };

    // Store the log entry.
    dst[entry_id as usize - 1] = log_entry;

    Ok(())
}
