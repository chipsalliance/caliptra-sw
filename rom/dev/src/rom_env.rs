/*++

Licensed under the Apache-2.0 license.

File Name:

    rom_env.rs

Abstract:

    File implements a context holding all the services utilized by ROM.
    The primary need for this abstraction is to hide the hardware details
    from the ROM flows. The natural side benefit of this abstraction is it
    makes authoring mocks and unit tests easy.

--*/

use crate::env_cell::EnvCell;
use caliptra_drivers::{
    DataVault, DeobfuscationEngine, DeviceState, Ecc384, FlowStatus, FuseBank, Hmac384, KeyVault,
    Mailbox, MfgState, PcrBank, ResetService, Sha1, Sha256, Sha384, Sha384Acc,
};

/// Rom Context
pub struct RomEnv {
    /// Deobfuscation engine
    doe: EnvCell<DeobfuscationEngine>,

    /// Reset Service
    reset: EnvCell<ResetService>,

    // SHA1 Engine
    sha1: EnvCell<Sha1>,

    // SHA2-256 Engine
    sha256: EnvCell<Sha256>,

    // SHA2-384 Engine
    sha384: EnvCell<Sha384>,

    // SHA2-384 Accelerator
    sha384_acc: EnvCell<Sha384Acc>,

    /// Hmac384 Engine
    hmac384: EnvCell<Hmac384>,

    /// Ecc384 Engine
    ecc384: EnvCell<Ecc384>,

    /// Key Vault
    key_vault: EnvCell<KeyVault>,

    /// Data Vault
    data_vault: EnvCell<DataVault>,

    /// Device state
    dev_state: EnvCell<DeviceState>,

    /// Manufacturing State
    mfg_state: EnvCell<MfgState>,

    /// Mailbox
    mbox: EnvCell<Mailbox>,

    /// Flow Status
    flow_status: EnvCell<FlowStatus>,

    /// Fuse Bank
    fuse_bank: EnvCell<FuseBank>,

    /// PCR Bank
    pcr_bank: EnvCell<PcrBank>,
}

impl Default for RomEnv {
    fn default() -> Self {
        Self {
            doe: EnvCell::new(DeobfuscationEngine::default()),
            reset: EnvCell::new(ResetService::default()),
            sha1: EnvCell::new(Sha1::default()),
            sha256: EnvCell::new(Sha256::default()),
            sha384: EnvCell::new(Sha384::default()),
            sha384_acc: EnvCell::new(Sha384Acc::default()),
            hmac384: EnvCell::new(Hmac384::default()),
            ecc384: EnvCell::new(Ecc384::default()),
            key_vault: EnvCell::new(KeyVault::default()),
            data_vault: EnvCell::new(DataVault::default()),
            dev_state: EnvCell::new(DeviceState::default()),
            mfg_state: EnvCell::new(MfgState::default()),
            mbox: EnvCell::new(Mailbox::default()),
            flow_status: EnvCell::new(FlowStatus::default()),
            fuse_bank: EnvCell::new(FuseBank::default()),
            pcr_bank: EnvCell::new(PcrBank::default()),
        }
    }
}

impl RomEnv {
    /// Get deobfuscation engine reference
    pub fn doe(&self) -> &EnvCell<DeobfuscationEngine> {
        &self.doe
    }

    /// Get reset service reference
    pub fn reset(&self) -> &EnvCell<ResetService> {
        &self.reset
    }

    /// Get SHA1 engine reference
    pub fn sha1(&self) -> &EnvCell<Sha1> {
        &self.sha1
    }

    /// Get SHA-256 engine reference
    pub fn sha256(&self) -> &EnvCell<Sha256> {
        &self.sha256
    }

    /// Get SHA-384 engine reference
    pub fn sha384(&self) -> &EnvCell<Sha384> {
        &self.sha384
    }

    /// Get SHA-384 accelerator reference
    pub fn sha384_acc(&self) -> &EnvCell<Sha384Acc> {
        &self.sha384_acc
    }

    /// Get HMAC-384 engine reference
    pub fn hmac384(&self) -> &EnvCell<Hmac384> {
        &self.hmac384
    }

    /// Get ECC-384 engine reference
    pub fn ecc384(&self) -> &EnvCell<Ecc384> {
        &self.ecc384
    }

    /// Get Key Vault reference
    pub fn key_vault(&self) -> &EnvCell<KeyVault> {
        &self.key_vault
    }

    /// Get Data Vault reference
    pub fn data_vault(&self) -> &EnvCell<DataVault> {
        &self.data_vault
    }

    /// Get Security state reference
    pub fn dev_state(&self) -> &EnvCell<DeviceState> {
        &self.dev_state
    }

    /// Get Manufacturing state reference
    pub fn mfg_state(&self) -> &EnvCell<MfgState> {
        &self.mfg_state
    }

    /// Get Mailbox
    pub fn mbox(&self) -> &EnvCell<Mailbox> {
        &self.mbox
    }

    /// Get Flow Status
    pub fn flow_status(&self) -> &EnvCell<FlowStatus> {
        &self.flow_status
    }

    /// Get Fuse Bank
    pub fn fuse_bank(&self) -> &EnvCell<FuseBank> {
        &self.fuse_bank
    }

    /// Get PCR Bank
    pub fn pcr_bank(&self) -> &EnvCell<PcrBank> {
        &self.pcr_bank
    }
}
