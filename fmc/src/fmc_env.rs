/*++

Licensed under the Apache-2.0 license.

File Name:

    fmc_env.rs

Abstract:

    File implements a context holding all the services utilized by firmware.
    The primary need for this abstraction is to hide the hardware details
    from the ROM/FMC/RT flows. The natural side benefit of this abstraction is it
    makes authoring mocks and unit tests easy.

--*/
use crate::fmc_env_cell::FmcEnvCell;

use caliptra_drivers::{
    DataVault, DeviceState, FlowStatus, FuseBank, Hmac384, KeyVault, Mailbox, MfgState, PcrBank,
    ResetService, Sha1, Sha256, Sha384, Sha384Acc,
};

/// Hardware Context
pub struct FmcEnv {
    /// Reset Service
    reset: FmcEnvCell<ResetService>,

    // SHA1 Engine
    sha1: FmcEnvCell<Sha1>,

    // SHA2-256 Engine
    sha256: FmcEnvCell<Sha256>,

    // SHA2-384 Engine
    sha384: FmcEnvCell<Sha384>,

    // SHA2-384 Accelerator
    sha384_acc: FmcEnvCell<Sha384Acc>,

    /// Hmac384 Engine
    hmac384: FmcEnvCell<Hmac384>,

    /// Key Vault
    key_vault: FmcEnvCell<KeyVault>,

    /// Data Vault
    data_vault: FmcEnvCell<DataVault>,

    /// Device state
    dev_state: FmcEnvCell<DeviceState>,

    /// Manufacturing State
    mfg_state: FmcEnvCell<MfgState>,

    /// Mailbox
    mbox: FmcEnvCell<Mailbox>,

    /// Flow Status
    flow_status: FmcEnvCell<FlowStatus>,

    /// Fuse Bank
    fuse_bank: FmcEnvCell<FuseBank>,

    /// PCR Bank
    pcr_bank: FmcEnvCell<PcrBank>,
}

impl Default for FmcEnv {
    fn default() -> Self {
        Self {
            reset: FmcEnvCell::new(ResetService::default()),
            sha1: FmcEnvCell::new(Sha1::default()),
            sha256: FmcEnvCell::new(Sha256::default()),
            sha384: FmcEnvCell::new(Sha384::default()),
            sha384_acc: FmcEnvCell::new(Sha384Acc::default()),
            hmac384: FmcEnvCell::new(Hmac384::default()),
            key_vault: FmcEnvCell::new(KeyVault::default()),
            data_vault: FmcEnvCell::new(DataVault::default()),
            dev_state: FmcEnvCell::new(DeviceState::default()),
            mfg_state: FmcEnvCell::new(MfgState::default()),
            mbox: FmcEnvCell::new(Mailbox::default()),
            flow_status: FmcEnvCell::new(FlowStatus::default()),
            fuse_bank: FmcEnvCell::new(FuseBank::default()),
            pcr_bank: FmcEnvCell::new(PcrBank::default()),
        }
    }
}

impl FmcEnv {
    /// Get reset service reference
    pub fn reset(&self) -> &FmcEnvCell<ResetService> {
        &self.reset
    }

    /// Get SHA1 engine reference
    pub fn sha1(&self) -> &FmcEnvCell<Sha1> {
        &self.sha1
    }

    /// Get SHA-256 engine reference
    pub fn sha256(&self) -> &FmcEnvCell<Sha256> {
        &self.sha256
    }

    /// Get SHA-384 engine reference
    pub fn sha384(&self) -> &FmcEnvCell<Sha384> {
        &self.sha384
    }

    /// Get SHA-384 accelerator reference
    pub fn sha384_acc(&self) -> &FmcEnvCell<Sha384Acc> {
        &self.sha384_acc
    }

    /// Get HMAC-384 engine reference
    pub fn hmac384(&self) -> &FmcEnvCell<Hmac384> {
        &self.hmac384
    }

    /// Get Key Vault reference
    pub fn key_vault(&self) -> &FmcEnvCell<KeyVault> {
        &self.key_vault
    }

    /// Get Data Vault reference
    pub fn data_vault(&self) -> &FmcEnvCell<DataVault> {
        &self.data_vault
    }

    /// Get Security state reference
    pub fn dev_state(&self) -> &FmcEnvCell<DeviceState> {
        &self.dev_state
    }

    /// Get Manufacturing state reference
    pub fn mfg_state(&self) -> &FmcEnvCell<MfgState> {
        &self.mfg_state
    }

    /// Get Mailbox
    pub fn mbox(&self) -> &FmcEnvCell<Mailbox> {
        &self.mbox
    }

    /// Get Flow Status
    pub fn flow_status(&self) -> &FmcEnvCell<FlowStatus> {
        &self.flow_status
    }

    /// Get Fuse Bank
    pub fn fuse_bank(&self) -> &FmcEnvCell<FuseBank> {
        &self.fuse_bank
    }

    /// Get PCR Bank
    pub fn pcr_bank(&self) -> &FmcEnvCell<PcrBank> {
        &self.pcr_bank
    }
}
