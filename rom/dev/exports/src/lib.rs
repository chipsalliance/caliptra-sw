// Licensed under the Apache-2.0 license

#![no_std]

use caliptra_error::{CaliptraResult, FromU32};

mod c_abi {
    // All these functions MUST have a u32 return value, as that is where the
    // CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT error will be returned if
    // the ROM hasn't implemented that method.
    extern "C" {
        pub fn caliptra_rom_run_fips_tests() -> u32;
        pub fn caliptra_rom_unimplemented_export_3() -> u32;
        pub fn caliptra_rom_unimplemented_export_4() -> u32;
        pub fn caliptra_rom_unimplemented_export_5() -> u32;
        pub fn caliptra_rom_unimplemented_export_6() -> u32;
        pub fn caliptra_rom_unimplemented_export_7() -> u32;
    }
}

/// Run all the FIPS tests implemented in the ROM. Caller is responsible for
/// handling any errors
///
/// # Safety
///
/// Caller must confirm that all cryptographic peripherals are in an idle state
/// and are ready to be used by the ROM.
#[inline(always)]
pub unsafe fn caliptra_rom_run_fips_tests() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_run_fips_tests() })
}

// Safe wrappers

#[inline(always)]
pub fn caliptra_rom_unimplemented_export_3() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_3() })
}
#[inline(always)]
pub fn caliptra_rom_unimplemented_export_4() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_4() })
}
#[inline(always)]
pub fn caliptra_rom_unimplemented_export_5() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_5() })
}
#[inline(always)]
pub fn caliptra_rom_unimplemented_export_6() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_6() })
}
#[inline(always)]
pub fn caliptra_rom_unimplemented_export_7() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_7() })
}
