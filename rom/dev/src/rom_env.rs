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
    DataVault, DeobfuscationEngine, Ecc384, Hmac384, KeyVault, Lms, Mailbox, PcrBank, Sha1, Sha256,
    Sha384, Sha384Acc, SocIfc,
};
use core::ops::Range;

const ICCM_START: u32 = 0x40000000;
const ICCM_SIZE: u32 = 128 << 10;

/// Rom Context
pub struct RomEnv {
    /// Deobfuscation engine
    doe: EnvCell<DeobfuscationEngine>,

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

    /// LMS Engine
    lms: EnvCell<Lms>,

    /// Key Vault
    key_vault: EnvCell<KeyVault>,

    /// Data Vault
    data_vault: EnvCell<DataVault>,

    /// SoC interface
    soc_ifc: EnvCell<SocIfc>,

    /// Mailbox
    mbox: EnvCell<Mailbox>,

    /// PCR Bank
    pcr_bank: EnvCell<PcrBank>,
}

impl Default for RomEnv {
    fn default() -> Self {
        Self {
            doe: EnvCell::new(DeobfuscationEngine::default()),
            sha1: EnvCell::new(Sha1::default()),
            sha256: EnvCell::new(Sha256::default()),
            sha384: EnvCell::new(Sha384::default()),
            sha384_acc: EnvCell::new(Sha384Acc::default()),
            hmac384: EnvCell::new(Hmac384::default()),
            ecc384: EnvCell::new(Ecc384::default()),
            lms: EnvCell::new(Lms::default()),
            key_vault: EnvCell::new(KeyVault::default()),
            data_vault: EnvCell::new(DataVault::default()),
            soc_ifc: EnvCell::new(SocIfc::default()),
            mbox: EnvCell::new(Mailbox::default()),
            pcr_bank: EnvCell::new(PcrBank::default()),
        }
    }
}

impl RomEnv {
    /// Get deobfuscation engine reference
    pub fn doe(&self) -> &EnvCell<DeobfuscationEngine> {
        &self.doe
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

    /// Get LMS engine reference
    pub fn lms(&self) -> &EnvCell<Lms> {
        &self.lms
    }

    /// Get Key Vault reference
    pub fn key_vault(&self) -> &EnvCell<KeyVault> {
        &self.key_vault
    }

    /// Get Data Vault reference
    pub fn data_vault(&self) -> &EnvCell<DataVault> {
        &self.data_vault
    }

    /// Get SoC interface reference
    pub fn soc_ifc(&self) -> &EnvCell<SocIfc> {
        &self.soc_ifc
    }

    /// Get Mailbox
    pub fn mbox(&self) -> &EnvCell<Mailbox> {
        &self.mbox
    }

    /// Get PCR Bank
    pub fn pcr_bank(&self) -> &EnvCell<PcrBank> {
        &self.pcr_bank
    }

    /// Get ICCM Range
    pub fn iccm_range(&self) -> Range<u32> {
        Range {
            start: ICCM_START,
            end: ICCM_START + ICCM_SIZE,
        }
    }
}
