/*++

Licensed under the Apache-2.0 license.

File Name:

    dice.rs

Abstract:

    DICE-related constants.

--*/

use caliptra_drivers::Lifecycle;

pub const FLAG_BIT_NOT_CONFIGURED: u32 = 1 << 0;
pub const FLAG_BIT_NOT_SECURE: u32 = 1 << 1;
pub const FLAG_BIT_DEBUG: u32 = 1 << 3;
pub const FLAG_BIT_FIXED_WIDTH: u32 = 1 << 31;

/// Generate flags for DICE evidence
///
/// # Arguments
///
/// * `device_lifecycle` - Device lifecycle
/// * `debug_locked`     - Debug locked
pub fn make_flags(device_lifecycle: Lifecycle, debug_locked: bool) -> [u8; 4] {
    let mut flags: u32 = FLAG_BIT_FIXED_WIDTH;

    flags |= match device_lifecycle {
        Lifecycle::Unprovisioned => FLAG_BIT_NOT_CONFIGURED,
        Lifecycle::Manufacturing => FLAG_BIT_NOT_SECURE,
        _ => 0,
    };

    if !debug_locked {
        flags |= FLAG_BIT_DEBUG;
    }

    flags.reverse_bits().to_be_bytes()
}
