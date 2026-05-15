// Licensed under the Apache-2.0 license

pub const ROM_VERSION_MAJOR: u16 = 2;
pub const ROM_VERSION_MINOR: u16 = 1;
pub const ROM_VERSION_PATCH: u16 = 1;

pub const FMC_VERSION_MAJOR: u16 = 2;
pub const FMC_VERSION_MINOR: u16 = 1;
pub const FMC_VERSION_PATCH: u16 = 0;

pub const RUNTIME_VERSION_MAJOR: u32 = 2;
pub const RUNTIME_VERSION_MINOR: u32 = 1;
pub const RUNTIME_VERSION_PATCH: u32 = 0;

/// Get the ROM version as a human-readable string (e.g., "2.1.1")
pub fn rom_version_string() -> String {
    format!(
        "{}.{}.{}",
        ROM_VERSION_MAJOR, ROM_VERSION_MINOR, ROM_VERSION_PATCH
    )
}

/// Get the FMC version as a human-readable string (e.g., "2.1.0")
pub fn fmc_version_string() -> String {
    format!(
        "{}.{}.{}",
        FMC_VERSION_MAJOR, FMC_VERSION_MINOR, FMC_VERSION_PATCH
    )
}

/// Get the Runtime version as a human-readable string (e.g., "2.1.0")
pub fn runtime_version_string() -> String {
    format!(
        "{}.{}.{}",
        RUNTIME_VERSION_MAJOR, RUNTIME_VERSION_MINOR, RUNTIME_VERSION_PATCH
    )
}

// ROM Version - 16 bits
// Major - 5 bits [15:11]
// Minor - 5 bits [10:6]
// Patch - 6 bits [5:0]
pub fn get_rom_version() -> u16 {
    ((ROM_VERSION_MAJOR & 0x1F) << 11)
        | ((ROM_VERSION_MINOR & 0x1F) << 6)
        | (ROM_VERSION_PATCH & 0x3F)
}

// FMC Version - 16 bits
// Major - 5 bits [15:11]
// Minor - 5 bits [10:6]
// Patch - 6 bits [5:0]
pub fn get_fmc_version() -> u16 {
    ((FMC_VERSION_MAJOR & 0x1F) << 11)
        | ((FMC_VERSION_MINOR & 0x1F) << 6)
        | (FMC_VERSION_PATCH & 0x3F)
}

// Runtime Version - 32 bits
// Major - 8 bits [31:24]
// Minor - 8 bits [23:16]
// Patch - 16 bits [15:0]
pub fn get_runtime_version() -> u32 {
    ((RUNTIME_VERSION_MAJOR & 0xFF) << 24)
        | ((RUNTIME_VERSION_MINOR & 0xFF) << 16)
        | (RUNTIME_VERSION_PATCH & 0xFFFF)
}
