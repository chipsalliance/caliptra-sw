/*++

Licensed under the Apache-2.0 license.

File Name:

    boot_status.rs

Abstract:

    MCU ROM boot status codes.

--*/

const ROM_INITIALIZATION_BASE: u32 = 1;
const LIFECYCLE_MANAGEMENT_BASE: u32 = 65;
const OTP_FUSE_OPERATIONS_BASE: u32 = 129;
const CALIPTRA_SETUP_BASE: u32 = 193;
const FIRMWARE_LOADING_BASE: u32 = 257;
const FIELD_ENTROPY_BASE: u32 = 321;
const BOOT_FLOW_BASE: u32 = 385;

/// Status codes used by MCU ROM to log boot progress.
#[repr(u32)]
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

impl From<McuRomBootStatus> for u32 {
    /// Converts to this type from the input type.
    fn from(status: McuRomBootStatus) -> u32 {
        status as u32
    }
}
