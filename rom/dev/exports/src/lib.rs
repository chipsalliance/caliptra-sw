// Licensed under the Apache-2.0 license

#![no_std]

use caliptra_error::{CaliptraResult, FromU32};

mod c_abi {
    // All these functions MUST have a u32 return value, as that is where the
    // CaliptraError::ROM_GLOBAL_UNIMPLEMENTED_EXPORT error will be returned if
    // the ROM hasn't implemented that method.
    extern "C" {
        pub fn caliptra_rom_unimplemented_export_2() -> u32;
        pub fn caliptra_rom_unimplemented_export_3() -> u32;
        pub fn caliptra_rom_unimplemented_export_4() -> u32;
        pub fn caliptra_rom_unimplemented_export_5() -> u32;
        pub fn caliptra_rom_unimplemented_export_6() -> u32;
        pub fn caliptra_rom_unimplemented_export_7() -> u32;
    }
}

// Safe wrappers

#[inline(always)]
pub fn caliptra_rom_unimplemented_export_2() -> CaliptraResult<()> {
    CaliptraResult::from_u32(unsafe { c_abi::caliptra_rom_unimplemented_export_2() })
}
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
