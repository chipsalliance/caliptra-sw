/*++
Licensed under the Apache-2.0 license.

File Name:

    fuse.rs

Abstract:

    The file contains Fuse-related Implementations.

--*/
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::{FuseLogEntry, FuseLogEntryId};
use caliptra_drivers::{CaliptraError, CaliptraResult, FuseLogArray};
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
#[cfg_attr(not(feature = "no-cfi"), cfi_mod_fn)]
pub fn log_fuse_data(
    log: &mut FuseLogArray,
    entry_id: FuseLogEntryId,
    data: &[u8],
) -> CaliptraResult<()> {
    if entry_id == FuseLogEntryId::Invalid {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_INVALID_ENTRY_ID);
    }

    // Create a FUSE log entry
    let mut log_entry = FuseLogEntry {
        entry_id: entry_id as u32,
        ..Default::default()
    };
    let Some(data_dest) = log_entry.log_data.as_bytes_mut().get_mut(..data.len()) else {
        return Err(CaliptraError::ROM_GLOBAL_FUSE_LOG_UNSUPPORTED_DATA_LENGTH);
    };
    data_dest.copy_from_slice(data);

    // Compiler will optimize out the bounds check because the largest
    // FuseLogEntryId is well within the bounds of the array. (double-checked
    // via panic_is_possible)
    log[entry_id as usize - 1] = log_entry;

    Ok(())
}
