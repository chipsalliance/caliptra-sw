/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_status.rs

Abstract:

    ROM boot status codes.

--*/

const IDEVID_BOOT_STATUS_BASE: u32 = 1;
const LDEVID_BOOT_STATUS_BASE: u32 = 65;
const FMCALIAS_BOOT_STATUS_BASE: u32 = 129;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
pub enum RomBootStatus {
    // Idevid Statuses
    IDevIdDecryptUdsComplete = IDEVID_BOOT_STATUS_BASE,
    IDevIdDecryptFeComplete = IDEVID_BOOT_STATUS_BASE + 1,
    IDevIdClearDoeSecretsComplete = IDEVID_BOOT_STATUS_BASE + 2,
    IDevIdCdiDerivationComplete = IDEVID_BOOT_STATUS_BASE + 3,
    IDevIdKeyPairDerivationComplete = IDEVID_BOOT_STATUS_BASE + 4,
    IDevIdSubjIdSnGenerationComplete = IDEVID_BOOT_STATUS_BASE + 5,
    IDevIdSubjKeyIdGenerationComplete = IDEVID_BOOT_STATUS_BASE + 6,
    IDevIdMakeCsrComplete = IDEVID_BOOT_STATUS_BASE + 7,
    IDevIdSendCsrComplete = IDEVID_BOOT_STATUS_BASE + 8,
    IDevIdDerivationComplete = IDEVID_BOOT_STATUS_BASE + 9,

    // Ldevid Statuses
    LDevIdCdiDerivationComplete = LDEVID_BOOT_STATUS_BASE,
    LDevIdKeyPairDerivationComplete = LDEVID_BOOT_STATUS_BASE + 1,
    LDevIdSubjIdSnGenerationComplete = LDEVID_BOOT_STATUS_BASE + 2,
    LDevIdSubjKeyIdGenerationComplete = LDEVID_BOOT_STATUS_BASE + 3,
    LDevIdCertSigGenerationComplete = LDEVID_BOOT_STATUS_BASE + 4,
    LDevIdDerivationComplete = LDEVID_BOOT_STATUS_BASE + 5,

    // FmcAlias Statuses
    FmcAliasDownloadImageComplete = FMCALIAS_BOOT_STATUS_BASE,
    FmcAliasManifestLoadComplete = FMCALIAS_BOOT_STATUS_BASE + 1,
    FmcAliasImageVerificationComplete = FMCALIAS_BOOT_STATUS_BASE + 2,
    FmcAliasPopulateDataVaultComplete = FMCALIAS_BOOT_STATUS_BASE + 3,
    FmcAliasExtendPcrComplete = FMCALIAS_BOOT_STATUS_BASE + 4,
    FmcAliasLoadImageComplete = FMCALIAS_BOOT_STATUS_BASE + 5,
    FmcAliasFirmwareDownloadTxComplete = FMCALIAS_BOOT_STATUS_BASE + 6,
    FmcAliasDeriveCdiComplete = FMCALIAS_BOOT_STATUS_BASE + 7,
    FmcAliasKeyPairDerivationComplete = FMCALIAS_BOOT_STATUS_BASE + 8,
    FmcAliasSubjIdSnGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 9,
    FmcAliasSubjKeyIdGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 10,
    FmcAliasCertSigGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 11,
    FmcAliasDerivationComplete = FMCALIAS_BOOT_STATUS_BASE + 12,
}

impl From<RomBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: RomBootStatus) -> u32 {
        status as u32
    }
}
