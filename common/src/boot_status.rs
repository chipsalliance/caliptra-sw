/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_status.rs

Abstract:

    ROM boot status codes.

--*/

const IDEVID_BOOT_STATUS_BASE: u32 = 1;
const LDEVID_BOOT_STATUS_BASE: u32 = 65;
const FWPROCESSOR_BOOT_STATUS_BASE: u32 = 129;
const FMCALIAS_BOOT_STATUS_BASE: u32 = 193;
const COLD_RESET_BOOT_STATUS_BASE: u32 = 257;
const UPDATE_RESET_BOOT_STATUS_BASE: u32 = 321;
const ROM_GLOBAL_BOOT_STATUS_BASE: u32 = 385;

/// Statuses used by ROM to log dice derivation progress.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    // Firmware Processor Statuses
    FwProcessorDownloadImageComplete = FWPROCESSOR_BOOT_STATUS_BASE,
    FwProcessorManifestLoadComplete = FWPROCESSOR_BOOT_STATUS_BASE + 1,
    FwProcessorImageVerificationComplete = FWPROCESSOR_BOOT_STATUS_BASE + 2,
    FwProcessorPopulateDataVaultComplete = FWPROCESSOR_BOOT_STATUS_BASE + 3,
    FwProcessorExtendPcrComplete = FWPROCESSOR_BOOT_STATUS_BASE + 4,
    FwProcessorLoadImageComplete = FWPROCESSOR_BOOT_STATUS_BASE + 5,
    FwProcessorFirmwareDownloadTxComplete = FWPROCESSOR_BOOT_STATUS_BASE + 6,
    FwProcessorComplete = FWPROCESSOR_BOOT_STATUS_BASE + 7,

    // FmcAlias Statuses
    FmcAliasDeriveCdiComplete = FMCALIAS_BOOT_STATUS_BASE,
    FmcAliasKeyPairDerivationComplete = FMCALIAS_BOOT_STATUS_BASE + 1,
    FmcAliasSubjIdSnGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 2,
    FmcAliasSubjKeyIdGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 3,
    FmcAliasCertSigGenerationComplete = FMCALIAS_BOOT_STATUS_BASE + 4,
    FmcAliasDerivationComplete = FMCALIAS_BOOT_STATUS_BASE + 5,

    // Cold Reset Statuses
    ColdResetStarted = COLD_RESET_BOOT_STATUS_BASE,
    ColdResetComplete = COLD_RESET_BOOT_STATUS_BASE + 1,

    // Update Reset Statuses
    UpdateResetStarted = UPDATE_RESET_BOOT_STATUS_BASE,
    UpdateResetLoadManifestComplete = UPDATE_RESET_BOOT_STATUS_BASE + 1,
    UpdateResetImageVerificationComplete = UPDATE_RESET_BOOT_STATUS_BASE + 2,
    UpdateResetExtendPcrComplete = UPDATE_RESET_BOOT_STATUS_BASE + 3,
    UpdateResetPopulateDataVaultComplete = UPDATE_RESET_BOOT_STATUS_BASE + 4,
    UpdateResetLoadImageComplete = UPDATE_RESET_BOOT_STATUS_BASE + 5,
    UpdateResetOverwriteManifestComplete = UPDATE_RESET_BOOT_STATUS_BASE + 6,
    UpdateResetComplete = UPDATE_RESET_BOOT_STATUS_BASE + 7,

    // ROM Global Boot Statues
    KatStarted = ROM_GLOBAL_BOOT_STATUS_BASE,
    KatComplete = ROM_GLOBAL_BOOT_STATUS_BASE + 1,
}

impl From<RomBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: RomBootStatus) -> u32 {
        status as u32
    }
}
