// Licensed under the Apache-2.0 license
use core::convert::From;
const RTALIAS_BOOT_STATUS_BASE: u32 = 0x400;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FmcBootStatus {
    // RtAlias Statuses
    RtMeasurementComplete = RTALIAS_BOOT_STATUS_BASE,
    RtAliasDeriveCdiComplete = RTALIAS_BOOT_STATUS_BASE + 1,
    RtAliasKeyPairDerivationComplete = RTALIAS_BOOT_STATUS_BASE + 2,
    RtAliasSubjIdSnGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 3,
    RtAliasSubjKeyIdGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 4,
    RtAliasCertSigGenerationComplete = RTALIAS_BOOT_STATUS_BASE + 5,
    RtAliasDerivationComplete = RTALIAS_BOOT_STATUS_BASE + 6,

    // Hash chain statuses
    RtHashChainComplete = RTALIAS_BOOT_STATUS_BASE + 7,
}

impl From<FmcBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: FmcBootStatus) -> u32 {
        status as u32
    }
}
