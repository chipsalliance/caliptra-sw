// Licensed under the Apache-2.0 license

use crate::{BootRegisters, ExpectedStage, StatusRegisters};
use caliptra_api_types::{DeviceLifecycle, Fuses};
use caliptra_common::mailbox_api::{GetIdevInfoResp, GetLdevCertResp};
use caliptra_error::CaliptraError;

/// Base functionality needed to run the tests. These are platform specific
/// and need to be implemented for each platform. For some platforms several of
/// these functions may not be applicable.
pub trait TestRunnerPlatform {
    /// Sets the fuse registers and set the CPTRA_FUSE_WR_DONE register
    fn init_fuses(&mut self, fuses: &Fuses) -> Result<(), Error>;

    /// Enables debug for the platform
    fn enable_debug(&mut self) -> Result<(), Error>;

    /// Sets the device lifecycle for the SoC. This will probably need to be
    /// translated to the lifecycle states the SoC uses at the platform level.
    fn set_device_lifecycle(&mut self, lifecycle: DeviceLifecycle) -> Result<(), Error>;

    /// Set Boot FSM go. Most platforms shouldn't need this functionality so a default
    /// implementation is provided.
    fn boot_fsm_go(&mut self) -> Result<(), Error> {
        Ok(())
    }

    /// Sets other registers required during early boot
    fn set_boot_registers(&mut self, regs: &BootRegisters) -> Result<(), Error>;

    /// Waits for the given boot stage (ready_for_fuses, ready_for_fw,
    /// ready_for_runtime) or the error if one occurs. For example, FMC_SVN_TOO_LOW.
    fn wait_for(&mut self, boot_stage: ExpectedStage) -> Result<(), Error>;

    /// Starts booting the platform
    fn boot(&mut self) -> Result<(), Error>;

    /// Upload FMC and RT image to Caliptra
    fn upload_firmware(&mut self, image_bundle: &[u8]) -> Result<(), Error>;

    /// Read all of the boot status and error registers
    fn read_status_regs(&mut self) -> Result<StatusRegisters, Error>;

    /// Gets the IDevID public keys
    fn get_idev_info(&mut self) -> Result<GetIdevInfoResp, Error>;

    /// Gets the LDevID certificate
    fn get_ldev_cert(&mut self) -> Result<GetLdevCertResp, Error>;

    /// Shutdown the platform
    fn shutdown(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub enum Error {
    Caliptra(CaliptraError),
    Platform(u32),
    OtherUdsOptionWithDebugEnabled,
    InvalidIdevCombo,
    DuplicateIDevPublicKey,
    DuplicateLDevPublicKey,
    InvalidIDevPublicKey,
    InvalidLDevPublicKey,
    SameLDevPublicKeyWhenShouldBeDifferent,
    IncorrectStatusRegs,
    IncorrectIDevPublicKey,
    IncorrectLDevPublicKey,
}
