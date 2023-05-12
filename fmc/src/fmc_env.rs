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
    DataVault, Ecc384, Hmac384, KeyVault, Mailbox, PcrBank, Sha1, Sha256, Sha384, Sha384Acc, SocIfc,
};

/// Hardware Context
pub struct FmcEnv {
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

    /// Ecc384 Engine
    ecc384: FmcEnvCell<Ecc384>,

    /// Key Vault
    key_vault: FmcEnvCell<KeyVault>,

    /// Data Vault
    data_vault: FmcEnvCell<DataVault>,

    /// Device state
    soc_ifc: FmcEnvCell<SocIfc>,

    /// Mailbox
    mbox: FmcEnvCell<Mailbox>,

    /// PCR Bank
    pcr_bank: FmcEnvCell<PcrBank>,
}

impl Default for FmcEnv {
    fn default() -> Self {
        Self {
            sha1: FmcEnvCell::new(Sha1::default()),
            sha256: FmcEnvCell::new(Sha256::default()),
            sha384: FmcEnvCell::new(Sha384::default()),
            sha384_acc: FmcEnvCell::new(Sha384Acc::default()),
            hmac384: FmcEnvCell::new(Hmac384::default()),
            ecc384: FmcEnvCell::new(Ecc384::default()),
            key_vault: FmcEnvCell::new(KeyVault::default()),
            data_vault: FmcEnvCell::new(DataVault::default()),
            soc_ifc: FmcEnvCell::new(SocIfc::default()),
            mbox: FmcEnvCell::new(Mailbox::default()),
            pcr_bank: FmcEnvCell::new(PcrBank::default()),
        }
    }
}

impl FmcEnv {
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
    pub fn soc_ifc(&self) -> &FmcEnvCell<SocIfc> {
        &self.soc_ifc
    }

    /// Get Mailbox
    pub fn mbox(&self) -> &FmcEnvCell<Mailbox> {
        &self.mbox
    }

    /// Get PCR Bank
    pub fn pcr_bank(&self) -> &FmcEnvCell<PcrBank> {
        &self.pcr_bank
    }

    /// Get ECC-384 engine reference
    pub fn ecc384(&self) -> &FmcEnvCell<Ecc384> {
        &self.ecc384
    }
}
