// Licensed under the Apache-2.0 license

pub const ROM_VERSION_MAJOR: u16 = 1;
pub const ROM_VERSION_MINOR: u16 = 0;
pub const ROM_VERSION_PATCH: u16 = 1;

// ROM Version - 16 bits
// Major - 5 bits [15:11]
// Minor - 5 bits [10:6]
// Patch - 6 bits [5:0]
pub fn get_rom_version() -> u16 {
    ((ROM_VERSION_MAJOR & 0x1F) << 11)
        | ((ROM_VERSION_MINOR & 0x1F) << 6)
        | (ROM_VERSION_PATCH & 0x3F)
}
