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

use caliptra_drivers::{
    DataVault, DeobfuscationEngine, Ecc384, Hmac384, KeyVault, Lms, Mailbox, PcrBank, Sha1, Sha256,
    Sha384, Sha384Acc, SocIfc,
};
use core::ops::Range;

const ICCM_START: u32 = 0x40000000;
const ICCM_SIZE: u32 = 128 << 10;

/// Rom Context
#[derive(Default)]
pub struct RomEnv {
    /// Deobfuscation engine
    pub doe: DeobfuscationEngine,

    // SHA1 Engine
    pub sha1: Sha1,

    // SHA2-256 Engine
    pub sha256: Sha256,

    // SHA2-384 Engine
    pub sha384: Sha384,

    // SHA2-384 Accelerator
    pub sha384_acc: Sha384Acc,

    /// Hmac384 Engine
    pub hmac384: Hmac384,

    /// Ecc384 Engine
    pub ecc384: Ecc384,

    /// LMS Engine
    pub lms: Lms,

    /// Key Vault
    pub key_vault: KeyVault,

    /// Data Vault
    pub data_vault: DataVault,

    /// SoC interface
    pub soc_ifc: SocIfc,

    /// Mailbox
    pub mbox: Mailbox,

    /// PCR Bank
    pub pcr_bank: PcrBank,
}

impl RomEnv {
    /// Get ICCM Range
    pub fn iccm_range(&self) -> Range<u32> {
        Range {
            start: ICCM_START,
            end: ICCM_START + ICCM_SIZE,
        }
    }
}
