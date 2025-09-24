/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_status.rs

Abstract:

    MCU ROM boot status codes.

--*/

use bitflags::bitflags;

const ROM_INITIALIZATION_BASE: u16 = 1;
const LIFECYCLE_MANAGEMENT_BASE: u16 = 65;
const OTP_FUSE_OPERATIONS_BASE: u16 = 129;
const CALIPTRA_SETUP_BASE: u16 = 193;
const FIRMWARE_LOADING_BASE: u16 = 257;
const FIELD_ENTROPY_BASE: u16 = 321;
const BOOT_FLOW_BASE: u16 = 385;

/// Status codes used by MCU ROM to log boot progress.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McuRomBootStatus {
    // ROM Initialization Statuses
    RomStarted = ROM_INITIALIZATION_BASE,
    McuMemoryMapInitialized = ROM_INITIALIZATION_BASE + 1,
    StrapsLoaded = ROM_INITIALIZATION_BASE + 2,
    McuRegistersInitialized = ROM_INITIALIZATION_BASE + 3,
    SocManagerInitialized = ROM_INITIALIZATION_BASE + 4,
    MciInitialized = ROM_INITIALIZATION_BASE + 5,
    ResetReasonDetected = ROM_INITIALIZATION_BASE + 6,

    // Lifecycle Management Statuses
    LifecycleControllerInitialized = LIFECYCLE_MANAGEMENT_BASE,
    LifecycleTransitionStarted = LIFECYCLE_MANAGEMENT_BASE + 1,
    LifecycleTransitionComplete = LIFECYCLE_MANAGEMENT_BASE + 2,
    LifecycleTokenBurningStarted = LIFECYCLE_MANAGEMENT_BASE + 3,
    LifecycleTokenBurningComplete = LIFECYCLE_MANAGEMENT_BASE + 4,

    // OTP and Fuse Operations
    OtpControllerInitialized = OTP_FUSE_OPERATIONS_BASE,
    FusesReadFromOtp = OTP_FUSE_OPERATIONS_BASE + 1,
    WatchdogConfigured = OTP_FUSE_OPERATIONS_BASE + 2,

    // Caliptra Setup Statuses
    CaliptraBootGoAsserted = CALIPTRA_SETUP_BASE,
    I3cInitialized = CALIPTRA_SETUP_BASE + 1,
    CaliptraReadyForFuses = CALIPTRA_SETUP_BASE + 2,
    AxiUsersConfigured = CALIPTRA_SETUP_BASE + 3,
    FusesPopulatedToCaliptra = CALIPTRA_SETUP_BASE + 4,
    FuseWriteComplete = CALIPTRA_SETUP_BASE + 5,
    CaliptraReadyForMailbox = CALIPTRA_SETUP_BASE + 6,

    // Firmware Loading Statuses
    RiDownloadFirmwareCommandSent = FIRMWARE_LOADING_BASE,
    RiDownloadFirmwareComplete = FIRMWARE_LOADING_BASE + 1,
    FlashRecoveryFlowStarted = FIRMWARE_LOADING_BASE + 2,
    FlashRecoveryFlowComplete = FIRMWARE_LOADING_BASE + 3,
    FirmwareReadyDetected = FIRMWARE_LOADING_BASE + 4,
    FirmwareValidationComplete = FIRMWARE_LOADING_BASE + 5,
    CaliptraRuntimeReady = FIRMWARE_LOADING_BASE + 6,

    // Field Entropy Programming
    FieldEntropyProgrammingStarted = FIELD_ENTROPY_BASE,
    FieldEntropyPartition0Complete = FIELD_ENTROPY_BASE + 1,
    FieldEntropyPartition1Complete = FIELD_ENTROPY_BASE + 2,
    FieldEntropyPartition2Complete = FIELD_ENTROPY_BASE + 3,
    FieldEntropyPartition3Complete = FIELD_ENTROPY_BASE + 4,
    FieldEntropyProgrammingComplete = FIELD_ENTROPY_BASE + 5,

    // Boot Flow Completion
    ColdBootFlowStarted = BOOT_FLOW_BASE,
    ColdBootFlowComplete = BOOT_FLOW_BASE + 1,
    WarmResetFlowStarted = BOOT_FLOW_BASE + 2,
    WarmResetFlowComplete = BOOT_FLOW_BASE + 3,
    FirmwareUpdateFlowStarted = BOOT_FLOW_BASE + 4,
    FirmwareUpdateFlowComplete = BOOT_FLOW_BASE + 5,
    HitlessUpdateFlowStarted = BOOT_FLOW_BASE + 6,
    HitlessUpdateFlowComplete = BOOT_FLOW_BASE + 7,
}

impl From<McuRomBootStatus> for u16 {
    /// Converts to this type from the input type.
    fn from(status: McuRomBootStatus) -> u16 {
        status as u16
    }
}

pub struct McuBootMilestones(u16);

bitflags! {
    impl McuBootMilestones: u16 {
        const ROM_STARTED                   = 0b1 << 0;
        const CPTRA_BOOT_GO_ASSERTED        = 0b1 << 1;
        const CPTRA_FUSES_WRITTEN           = 0b1 << 2;
        const RI_DOWNLOAD_COMPLETED         = 0b1 << 3;
        const FLASH_RECOVERY_FLOW_COMPLETED = 0b1 << 4;
        const COLD_BOOT_FLOW_COMPLETE       = 0b1 << 5;
    }
}

impl From<u16> for McuBootMilestones {
    fn from(value: u16) -> McuBootMilestones {
        McuBootMilestones(value)
    }
}

impl From<McuBootMilestones> for u16 {
    fn from(value: McuBootMilestones) -> u16 {
        value.0
    }
}
