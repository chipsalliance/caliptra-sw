// Licensed under the Apache-2.0 license
use core::convert::From;
const RTALIAS_BOOT_STATUS_BASE: u32 = 0x400;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FmcBootStatus {
    // RtAlias Statuses
    RtAliasDeriveCdiComplete = RTALIAS_BOOT_STATUS_BASE,
    RtAliasKeyPairDerivationComplete = RTALIAS_BOOT_STATUS_BASE + 1,
    RtAliasSubjIdSnGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 2,
    RtAliasSubjKeyIdGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 3,
    RtAliasCertSigGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 4,
    RtAliasDerivationComplete = RTALIAS_BOOT_STATUS_BASE + 5,
}

impl From<FmcBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: FmcBootStatus) -> u32 {
        status as u32
    }
}
