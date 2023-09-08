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

use crate::fht::FhtDataStore;
use caliptra_common::memory_layout::*;
use caliptra_drivers::{
    DataVault, DeobfuscationEngine, Ecc384, Hmac384, KeyVault, Lms, Mailbox, PcrBank,
    PersistentDataAccessor, Sha1, Sha256, Sha384, Sha384Acc, SocIfc, Trng,
};
use caliptra_error::CaliptraResult;
use caliptra_registers::{
    csrng::CsrngReg, doe::DoeReg, dv::DvReg, ecc::EccReg, entropy_src::EntropySrcReg,
    hmac::HmacReg, kv::KvReg, mbox::MboxCsr, pv::PvReg, sha256::Sha256Reg, sha512::Sha512Reg,
    sha512_acc::Sha512AccCsr, soc_ifc::SocIfcReg, soc_ifc_trng::SocIfcTrngReg,
};
use core::ops::Range;

/// Rom Context
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

    /// FHT Data Store
    pub fht_data_store: FhtDataStore,

    /// Cryptographically Secure Random Number Generator
    pub trng: Trng,

    // Mechanism to access the persistent data safely
    pub persistent_data: PersistentDataAccessor,
}

impl RomEnv {
    pub const ICCM_RANGE: Range<u32> = Range {
        start: ICCM_ORG,
        end: ICCM_ORG + ICCM_SIZE,
    };

    pub unsafe fn new_from_registers() -> CaliptraResult<Self> {
        let trng = Trng::new(
            CsrngReg::new(),
            EntropySrcReg::new(),
            SocIfcTrngReg::new(),
            &SocIfcReg::new(),
        )?;

        Ok(Self {
            doe: DeobfuscationEngine::new(DoeReg::new()),
            sha1: Sha1::default(),
            sha256: Sha256::new(Sha256Reg::new()),
            sha384: Sha384::new(Sha512Reg::new()),
            sha384_acc: Sha384Acc::new(Sha512AccCsr::new()),
            hmac384: Hmac384::new(HmacReg::new()),
            ecc384: Ecc384::new(EccReg::new()),
            lms: Lms::default(),
            key_vault: KeyVault::new(KvReg::new()),
            data_vault: DataVault::new(DvReg::new()),
            soc_ifc: SocIfc::new(SocIfcReg::new()),
            mbox: Mailbox::new(MboxCsr::new()),
            pcr_bank: PcrBank::new(PvReg::new()),
            fht_data_store: FhtDataStore::default(),
            trng,
            persistent_data: PersistentDataAccessor::new(),
        })
    }
}
